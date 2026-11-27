// driver.go 是会话驱动的统一构造入口（v0.6.5）：给定一条 sessions 表记录
// （secret 已解密），按 kind 建出对应的 Session 实现。agent 工具与 server
// HTTP 层共用，避免两处各写一份 kind 分发。
package session

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// httpsSecret 是 http_* 会话 secret 的 JSON 结构（落库时 AES-GCM 加密）。
type httpsSecret struct {
	Password       string            `json:"password"`
	Encoder        string            `json:"encoder"`
	ScriptType     string            `json:"script_type"`
	AllowPlaintext bool              `json:"allow_plaintext"`
	Headers        map[string]string `json:"headers"`
	Proxy          string            `json:"proxy"`
	TimeoutSec     int               `json:"timeout_sec"`
}

// reverseSecret 是 reverse 会话 secret 的 JSON 结构。
type reverseSecret struct {
	PenSessionID int    `json:"pen_session_id"`
	MCPURL       string `json:"mcp_url"`
	Token        string `json:"token"`
}

// DriverFor 按记录建驱动。reverse 会话需要 penelope MCP 调用器（caller）；
// http 会话不需要（caller 可为 nil）。ssh 为预留类型，暂无驱动，诚实报错。
func DriverFor(rec *db.SessionRecord, caller MCPCaller) (Session, error) {
	if rec == nil {
		return nil, opError("probe", "会话记录为空")
	}
	switch rec.Kind {
	case db.SessionHTTP, db.SessionHTTPJSP, db.SessionHTTPASPX:
		var sec httpsSecret
		if strings.TrimSpace(rec.Secret) != "" {
			if err := json.Unmarshal([]byte(rec.Secret), &sec); err != nil {
				return nil, opError("probe", "会话 secret 解析失败: %v", err)
			}
		}
		timeout := time.Duration(sec.TimeoutSec) * time.Second
		script := sec.ScriptType
		if script == "" {
			switch rec.Kind {
			case db.SessionHTTP:
				script = "php"
			case db.SessionHTTPJSP:
				script = "jsp"
			case db.SessionHTTPASPX:
				script = "aspx"
			}
		}
		return NewHTTPShell(rec.ID, rec.Kind, HTTPShellConfig{
			URL: rec.URL, ScriptType: script, Password: sec.Password,
			Encoder: sec.Encoder, Timeout: timeout,
			AllowPlaintext: sec.AllowPlaintext, ExtraHeaders: sec.Headers, Proxy: sec.Proxy,
		})
	case db.SessionReverse:
		var sec reverseSecret
		if strings.TrimSpace(rec.Secret) != "" {
			if err := json.Unmarshal([]byte(rec.Secret), &sec); err != nil {
				return nil, opError("probe", "会话 secret 解析失败: %v", err)
			}
		}
		if caller == nil {
			return nil, opError("probe", "reverse 会话需要 penelope handler（MCP 调用器未就绪），无法建驱动")
		}
		return NewPenelopeSession(rec.ID, sec.PenSessionID, caller)
	default:
		return nil, fmt.Errorf("会话类型 %q 暂无驱动（ssh 为预留类型）", rec.Kind)
	}
}
