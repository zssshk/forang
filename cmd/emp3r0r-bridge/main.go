// emp3r0r-bridge — FORANG ↔ emp3r0r 融合桥（宿主机侧组件）。
//
// 职责：持有 emp3r0r operator 凭据（WireGuard），spawn `emp3r0r mcp` 子进程
// 作为 MCP stdio client，把 emp3r0r 的目标/执行/job 输出封装成 localhost REST，
// 供 FORANG server 的 emp3r0r 适配层调用。
//
// 信任边界：WG 凭据只在本进程（宿主机）内；FORANG 容器仅拿到受 token 保护的
// localhost API——面板容器被攻破不直接等于 emp3r0r operator 凭据泄露
// （对齐 emp3r0r 文档的隔离要求：MCP 面只在专用环境持有凭据）。
//
// 端点（全部需 X-Bridge-Token）：
//
//	GET  /status                  桥与 MCP server 健康 + 活跃目标
//	GET  /agents                  list_agents 原始结果
//	POST /exec {agent, cmd}       select_agent → run_module(exec) → 轮询 job 输出
//	GET  /job?id=&tail=           read_job_output
//
// 配置（环境变量）：
//
//	EMP3R0R_BIN      emp3r0r 可执行路径（默认 /usr/local/bin/emp3r0r）
//	EMP3R0R_BRIDGE_TOKEN  REST 认证 token（必填，未设拒绝启动）
//	EMP3R0R_BRIDGE_ADDR   监听地址（默认 127.0.0.1:18660）
//	EMP3R0R_EXEC_TIMEOUT  单命令同步等待上限（默认 60s）
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type mcpClient struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Reader
	nextID  int64
	ready   bool
	workdir string
}

type rpcResp struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func newMCPClient(bin string) (*mcpClient, error) {
	cmd := exec.Command(bin, "mcp")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = io.Discard // MCP stdio 只允许 JSON 走 stdout
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn %s mcp: %w", bin, err)
	}
	c := &mcpClient{cmd: cmd, stdin: stdin, stdout: bufio.NewReaderSize(stdout, 1<<20), nextID: 1}
	if err := c.initialize(); err != nil {
		cmd.Process.Kill()
		return nil, err
	}
	c.ready = true
	return c, nil
}

func (c *mcpClient) call(method string, params any, timeout time.Duration) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	id := c.nextID
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	b, _ := json.Marshal(req)
	if _, err := c.stdin.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	deadline := time.After(timeout)
	for {
		lineCh := make(chan string, 1)
		errCh := make(chan error, 1)
		go func() {
			line, err := c.stdout.ReadString('\n')
			if err != nil {
				errCh <- err
				return
			}
			lineCh <- line
		}()
		select {
		case <-deadline:
			return nil, fmt.Errorf("mcp call %s 超时", method)
		case err := <-errCh:
			return nil, fmt.Errorf("mcp stdout: %w", err)
		case line := <-lineCh:
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var resp rpcResp
			if err := json.Unmarshal([]byte(line), &resp); err != nil {
				continue // 非 JSON 行（server 启动杂音）跳过
			}
			var gotID int64
			_ = json.Unmarshal(resp.ID, &gotID)
			if gotID != id {
				continue // 不属于本次请求（notification 等）
			}
			if resp.Error != nil {
				return nil, fmt.Errorf("mcp error %d: %s", resp.Error.Code, resp.Error.Message)
			}
			return resp.Result, nil
		}
	}
}

func (c *mcpClient) initialize() error {
	id := struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int64  `json:"id"`
		Method  string `json:"method"`
		Params  any    `json:"params"`
	}{Params: map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "emp3r0r-bridge", "version": "0.1.0"},
	}}
	b, _ := json.Marshal(id)
	if _, err := c.stdin.Write(append(b, '\n')); err != nil {
		return err
	}
	// 读取并丢弃 initialize 响应（内容含 workflow/OPSEC 指引，bridge 不消费）
	deadline := time.After(30 * time.Second)
	for {
		select {
		case <-deadline:
			return fmt.Errorf("initialize 超时")
		default:
			line, err := c.stdout.ReadString('\n')
			if err != nil {
				return err
			}
			var resp rpcResp
			if json.Unmarshal([]byte(strings.TrimSpace(line)), &resp) == nil && len(resp.ID) > 0 {
				if resp.Error != nil {
					return fmt.Errorf("initialize: %s", resp.Error.Message)
				}
				// 发 initialized 通知
				note := map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}
				nb, _ := json.Marshal(note)
				_, _ = c.stdin.Write(append(nb, '\n'))
				return nil
			}
		}
	}
}

func (c *mcpClient) tool(name string, args map[string]any, timeout time.Duration) (string, error) {
	params := map[string]any{"name": name, "arguments": args}
	res, err := c.call("tools/call", params, timeout)
	if err != nil {
		return "", err
	}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(res, &out); err != nil {
		return string(res), nil
	}
	var sb strings.Builder
	for _, c := range out.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
		}
	}
	if out.IsError {
		return sb.String(), fmt.Errorf("%s", sb.String())
	}
	return sb.String(), nil
}

// ---------- REST ----------

type bridge struct {
	mcp        *mcpClient
	token      string
	execLimit  time.Duration
	mu         sync.Mutex
	lastTarget string
}

func (b *bridge) auth(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Bridge-Token") != b.token {
		http.Error(w, `{"detail":"bridge token 无效"}`, http.StatusUnauthorized)
		return false
	}
	return true
}

func (b *bridge) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// selectIfChanged 目标未选中或换了就重新 select_agent（单持有者锁）。
func (b *bridge) selectIfChanged(agent string) error {
	b.mu.Lock()
	cur := b.lastTarget
	b.mu.Unlock()
	if cur == agent {
		return nil
	}
	if _, err := b.mcp.tool("select_agent", map[string]any{"agent": agent}, 30*time.Second); err != nil {
		return fmt.Errorf("select_agent: %w", err)
	}
	b.mu.Lock()
	b.lastTarget = agent
	b.mu.Unlock()
	return nil
}

func (b *bridge) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !b.auth(w, r) {
		return
	}
	alive := b.mcp != nil && b.mcp.ready && b.mcp.cmd.Process != nil
	active := ""
	if b.mcp != nil {
		b.mu.Lock()
		active = b.lastTarget
		b.mu.Unlock()
	}
	b.writeJSON(w, map[string]any{"data": map[string]any{
		"bridge": "up", "mcp_alive": alive, "active_target": active,
	}})
}

func (b *bridge) handleAgents(w http.ResponseWriter, r *http.Request) {
	if !b.auth(w, r) {
		return
	}
	out, err := b.mcp.tool("list_agents", map[string]any{}, 60*time.Second)
	if err != nil {
		b.writeJSON(w, map[string]any{"detail": err.Error()})
		return
	}
	b.writeJSON(w, map[string]any{"data": out})
}

func (b *bridge) handleExec(w http.ResponseWriter, r *http.Request) {
	if !b.auth(w, r) {
		return
	}
	var req struct {
		Agent string `json:"agent"`
		Cmd   string `json:"cmd"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)
	if req.Agent == "" || req.Cmd == "" {
		b.writeJSON(w, map[string]any{"detail": "agent 与 cmd 必填"})
		return
	}
	if err := b.selectIfChanged(req.Agent); err != nil {
		b.writeJSON(w, map[string]any{"detail": err.Error()})
		return
	}
	// run_module exec：BOF 经 coffloader_linux 内存加载（Linux 目标）
	res, err := b.mcp.tool("run_module", map[string]any{
		"module": "exec", "flags": map[string]any{"cmd": req.Cmd, "mode": "shell"},
	}, b.execLimit)
	if err != nil {
		b.writeJSON(w, map[string]any{"detail": err.Error()})
		return
	}
	b.writeJSON(w, map[string]any{"data": res})
}

func (b *bridge) handleJob(w http.ResponseWriter, r *http.Request) {
	if !b.auth(w, r) {
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		b.writeJSON(w, map[string]any{"detail": "id 必填"})
		return
	}
	tail := r.URL.Query().Get("tail")
	args := map[string]any{"job": id}
	if tail != "" {
		args["tail"] = json.Number(tail)
	}
	out, err := b.mcp.tool("read_job_output", args, 30*time.Second)
	if err != nil {
		b.writeJSON(w, map[string]any{"detail": err.Error()})
		return
	}
	b.writeJSON(w, map[string]any{"data": out})
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	token := os.Getenv("EMP3R0R_BRIDGE_TOKEN")
	if token == "" {
		log.Fatal("拒绝启动：未设置 EMP3R0R_BRIDGE_TOKEN")
	}
	bin := envOr("EMP3R0R_BIN", "/usr/local/bin/emp3r0r")
	addr := envOr("EMP3R0R_BRIDGE_ADDR", "127.0.0.1:18660")
	limit, err := time.ParseDuration(envOr("EMP3R0R_EXEC_TIMEOUT", "60s"))
	if err != nil {
		limit = 60 * time.Second
	}
	mcp, err := newMCPClient(bin)
	if err != nil {
		log.Fatalf("MCP server 启动失败: %v", err)
	}
	b := &bridge{mcp: mcp, token: token, execLimit: limit}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", b.handleStatus)
	mux.HandleFunc("GET /agents", b.handleAgents)
	mux.HandleFunc("POST /exec", b.handleExec)
	mux.HandleFunc("GET /job", b.handleJob)
	log.Printf("emp3r0r-bridge listening on %s (mcp pid=%d)", addr, mcp.cmd.Process.Pid)
	log.Fatal(http.ListenAndServe(addr, mux))
}
