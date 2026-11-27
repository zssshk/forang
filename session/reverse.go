// reverse.go 是受管 penelope handler（v0.6.5 artex-ymh 移植，内网渗透期 5）：
// penelope 进程（penelope.py --mcp，本地 token 认证，默认只绑 127.0.0.1）
// + MCP 桥（把 penelope 会话同步进 sessions 台账 kind="reverse"，与进程内
// Registry 联动）。同步后 session_exec/session_read/session_write 与内网
// 会话面板自动可用，无需改前端。
//
// penelope MCP API 结论（artex-ymh 实测 + penelope.py MCPServer 源码）：
//   - 端点 POST /（GET 405）；Authorization: Bearer <token>；响应普通
//     application/json（非 SSE）；协议版本 2025-06-18；
//   - 工具 6 个，结果均为单 text block 内嵌 JSON；文件传输要求持久 shell
//     （agent 或 auto-upgrade 后的 PTY），否则返回 error；
//   - penelope 无回连口令：监听默认只绑 127.0.0.1，目标直连回连时
//     reverse_listen 需显式 iface；加密不指望它（走加密马/隧道）。
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/Autumn-27/artex/mcphttp"
)

// reverseSyncInterval 是 handler 存活期间会话同步（watchdog）的轮询间隔。
const reverseSyncInterval = 10 * time.Second

// reverseStartTimeout 是等 penelope MCP 端口就绪的上限。
const reverseStartTimeout = 15 * time.Second

// defaultReversePort 是 reverse_listen 未指定 port 时的默认反弹监听口。
const defaultReversePort = 4444

// ReverseManager 管一个 penelope handler 进程 + 它的 MCP 调用器。
// Bin 为空时只连现成 MCP 端点（ARTEX_PENELOPE_MCP_URL）；Bin 有值时按
// penelope.py MCP 模式拉起进程（--mcp --port <port> --token <token>）。
type ReverseManager struct {
	mu      sync.Mutex
	bin     string // penelope.py 路径（空=不拉进程，只连现成端点）
	mcpURL  string
	token   string
	cmd     *exec.Cmd
	caller  MCPCaller
	running bool
}

// NewReverseManager 构造 handler 管理器。mcpURL 为空时默认
// http://127.0.0.1:<port>/（penelope MCP 端点在根路径 POST /）。
func NewReverseManager(bin, mcpURL string) *ReverseManager {
	return &ReverseManager{bin: bin, mcpURL: mcpURL}
}

// Start 拉起（或连接）penelope handler 并做 MCP 握手；失败返回带 stderr 的
// 诚实错误，不谎报就绪。
func (m *ReverseManager) Start(ctx context.Context, port int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running && m.caller != nil {
		return nil
	}
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("penelope token 生成失败: %w", err)
	}
	m.token = hex.EncodeToString(tokenBytes)
	url := m.mcpURL
	if url == "" {
		if m.bin == "" {
			return fmt.Errorf("penelope 未配置：既无 ARTEX_PENELOPE_MCP_URL，也无 penelope.py 可拉起")
		}
		if port <= 0 {
			port = defaultReversePort
		}
		url = fmt.Sprintf("http://127.0.0.1:%d/", port)
		if err := m.spawn(url, port); err != nil {
			return err
		}
	}
	caller, err := mcphttp.New(ctx, "penelope", url, map[string]string{
		"Authorization": "Bearer " + m.token,
	}, false)
	if err != nil {
		m.stopLocked()
		return fmt.Errorf("penelope MCP 握手失败（%s）: %w", url, err)
	}
	m.caller = caller
	m.mcpURL = url
	m.running = true
	return nil
}

// spawn 拉起 penelope.py 进程并等 MCP 端口就绪（15 秒上限）。
func (m *ReverseManager) spawn(url string, port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("penelope 监听口 %d 已被占用: %w", port, err)
	}
	_ = ln.Close()
	cmd := exec.Command("python3", m.bin, "--mcp", "--port", fmt.Sprint(port), "--token", m.token)
	cmd.Stdout = nil
	errBuf := &limitedBuffer{limit: 4096}
	cmd.Stderr = errBuf
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("penelope 拉起失败（%s）: %w", m.bin, err)
	}
	m.cmd = cmd
	deadline := time.Now().Add(reverseStartTimeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if cmd.ProcessState != nil {
			return fmt.Errorf("penelope 进程启动后即退出: %s", errBuf.String())
		}
		time.Sleep(500 * time.Millisecond)
	}
	m.stopLocked()
	return fmt.Errorf("penelope MCP 端口 %d 在 %s 内未就绪: %s", port, reverseStartTimeout, errBuf.String())
}

// Caller 返回 MCP 调用器（未 Start 时为 nil）。
func (m *ReverseManager) Caller() MCPCaller {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.caller
}

// MCPURL 返回当前 MCP 端点 URL（未 Start 时为空串）。
func (m *ReverseManager) MCPURL() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mcpURL
}

// Token 返回当前 MCP 认证 token（未 Start 时为空串；只存内存，不落库）。
func (m *ReverseManager) Token() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.token
}

// Running 报告 handler 是否已就绪。
func (m *ReverseManager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// Stop 停掉 handler 进程并断开 MCP（不 kill 远端反弹 shell 会话——
// 那些会话已同步进 sessions 台账，状态由心跳/watchdog 另行标记）。
func (m *ReverseManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
}

func (m *ReverseManager) stopLocked() {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
		_, _ = m.cmd.Process.Wait()
	}
	m.cmd = nil
	m.caller = nil
	m.running = false
}

// limitedBuffer 是定长 stderr 收集器（只留尾部，避免日志爆炸）。
type limitedBuffer struct {
	buf   []byte
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.limit {
		b.buf = b.buf[len(b.buf)-b.limit:]
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string { return string(b.buf) }
