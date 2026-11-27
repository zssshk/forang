// penelope.go 是反弹 shell 会话驱动（v0.6.5 artex-ymh 移植）：把立足点
// Session 接口落到 penelope MCP handler 上。penelope 是外部进程
// （penelope.py --mcp，本地 token 认证，默认只绑 127.0.0.1），本驱动只调
// 它的 6 个 MCP 工具：list_sessions / get_session_info / exec_in_session /
// kill_session / upload_to_session / download_from_session。
//
// 诚实边界：handler 未就绪（进程未起 / MCP 不通 / 会话已消失）一律返回带
// 语义的错误，不伪造输出；Close 只断开本地引用，不 kill 远端 shell
// （kill 须经显式操作，避免一次 registry 驱逐误杀他人会话）。
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MCPCaller 是反弹 shell 驱动依赖的最小 MCP 调用面（*mcphttp.Client 满足；
// 单测注入假实现）。
type MCPCaller interface {
	Call(ctx context.Context, tool string, args any) (string, error)
}

// PenSession 是 penelope list_sessions/get_session_info 一条会话的投影。
type PenSession struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	OS       string `json:"OS"`
	Type     string `json:"type"`
	User     string `json:"user"`
	Source   string `json:"source"`
	Hostname string `json:"hostname,omitempty"`
	System   string `json:"system,omitempty"`
	Arch     string `json:"arch,omitempty"`
	CWD      string `json:"cwd,omitempty"`
}

// PenelopeSession 是 Session 接口的 penelope 反弹 shell 实现。
// penID 是 penelope 侧会话 id（非 FORANG sessions 表主键）。
type PenelopeSession struct {
	id     int64 // sessions 表主键
	penID  int
	caller MCPCaller
}

// NewPenelopeSession 构造反弹 shell 会话驱动。
func NewPenelopeSession(id int64, penID int, caller MCPCaller) (*PenelopeSession, error) {
	if caller == nil {
		return nil, opError("probe", "penelope MCP 调用器为空，handler 未就绪")
	}
	if penID <= 0 {
		return nil, opError("probe", "penelope 会话 id 非法")
	}
	return &PenelopeSession{id: id, penID: penID, caller: caller}, nil
}

func (p *PenelopeSession) ID() int64    { return p.id }
func (p *PenelopeSession) Kind() string { return "reverse" }

// PenID 返回 penelope 侧会话 id。
func (p *PenelopeSession) PenID() int { return p.penID }

// Test 查 penelope 侧会话是否还活着（get_session_info）。
func (p *PenelopeSession) Test(ctx context.Context) error {
	_, err := p.info(ctx)
	return err
}

func (p *PenelopeSession) info(ctx context.Context) (*PenSession, error) {
	text, err := p.caller.Call(ctx, "get_session_info", map[string]any{"session_id": p.penID})
	if err != nil {
		return nil, opError("test", "penelope 会话 %d 已消失或 handler 不通: %v", p.penID, err)
	}
	var info PenSession
	if err := json.Unmarshal([]byte(text), &info); err != nil {
		return nil, opError("test", "penelope 会话信息解析失败: %v", err)
	}
	return &info, nil
}

// Exec 在反弹 shell 里执行命令（stdout/stderr 已合并，stderr 恒为空）。
func (p *PenelopeSession) Exec(ctx context.Context, cmd string, timeout time.Duration) (string, string, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	text, err := p.caller.Call(ctx, "exec_in_session", map[string]any{
		"session_id": p.penID, "command": cmd,
	})
	if err != nil {
		return "", "", opError("exec", "penelope 执行失败: %v", err)
	}
	var out struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		// 非 JSON 即当原文输出（penelope 文本块内嵌 JSON，异常时宁可原文返回也不丢）。
		return text, "", nil
	}
	return out.Output, "", nil
}

// ReadFile 从反弹 shell 会话下载文件（penelope 落到 handler 主机本地，
// 再由本驱动读回；handler 与 artex 不同机时返回诚实错误）。
func (p *PenelopeSession) ReadFile(ctx context.Context, path string) ([]byte, error) {
	text, err := p.caller.Call(ctx, "download_from_session", map[string]any{
		"session_id": p.penID, "remote_path": path,
	})
	if err != nil {
		return nil, opError("read", "penelope 下载失败: %v", err)
	}
	var dl struct {
		Downloaded []string `json:"downloaded"`
	}
	if err := json.Unmarshal([]byte(text), &dl); err != nil || len(dl.Downloaded) == 0 {
		return nil, opError("read", "penelope 未返回下载路径（handler 可能与 artex 不同机）: %s", strings.TrimSpace(text))
	}
	data, err := os.ReadFile(dl.Downloaded[0])
	if err != nil {
		return nil, opError("read", "下载文件本地不可读（handler 可能与 artex 不同机）: %v", err)
	}
	return data, nil
}

// WriteFile 向反弹 shell 会话上传文件（先写本地临时文件再调 upload）。
func (p *PenelopeSession) WriteFile(ctx context.Context, path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp("", "penelope-upload-*")
	if err != nil {
		return opError("write", "本地临时文件创建失败: %v", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return opError("write", "本地临时文件写入失败: %v", err)
	}
	_ = tmp.Close()
	if _, err := p.caller.Call(ctx, "upload_to_session", map[string]any{
		"session_id": p.penID, "local_path": tmpName, "remote_path": dir,
	}); err != nil {
		return opError("write", "penelope 上传失败（须持久 shell，文件传输要求 PTY 升级后的会话）: %v", err)
	}
	return nil
}

// Kill 显式杀掉 penelope 侧会话（Close 不调它）。
func (p *PenelopeSession) Kill(ctx context.Context) error {
	_, err := p.caller.Call(ctx, "kill_session", map[string]any{"session_id": p.penID})
	return err
}

// Close 只断开本地引用，不 kill 远端 shell。
func (p *PenelopeSession) Close(ctx context.Context) error { return nil }

// ListPenelopeSessions 列出 handler 侧全部反弹会话（同步进台账用）。
func ListPenelopeSessions(ctx context.Context, caller MCPCaller) ([]PenSession, error) {
	text, err := caller.Call(ctx, "list_sessions", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("penelope list_sessions 失败: %w", err)
	}
	var res struct {
		Sessions []PenSession `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(text), &res); err != nil {
		return nil, fmt.Errorf("penelope 会话列表解析失败: %w", err)
	}
	return res.Sessions, nil
}
