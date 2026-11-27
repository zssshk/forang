// sessions.go 是立足点会话的落库层（schema.sql §M，v0.6.5 artex-ymh 移植）。
// secret（连接参数 JSON）用 AES-GCM 加密存储：密钥由 jwt.key 经 SHA-256 域分离
// 派生（域标签 artex/sessions/v1），与凭据库密钥隔离；密钥缺失时加解密直接
// 报错，绝不明文落库。status 只记 alive/dead；失联（stale）由 last_beat
// 现算（StaleAfter），不落库。
package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// 立足点会话类型（schema CHECK 与 Go 校验同源）。
const (
	SessionHTTP     = "http_php"
	SessionHTTPJSP  = "http_jsp"
	SessionHTTPASPX = "http_aspx"
	SessionReverse  = "reverse"
	SessionSSH      = "ssh"
)

// 会话状态。
const (
	SessionAlive = "alive"
	SessionDead  = "dead"
)

// StaleAfter 是心跳失联阈值：alive 会话 last_beat 超过该时长未刷新即判 stale。
const StaleAfter = 10 * time.Minute

// ValidSessionKind 校验会话类型。
func ValidSessionKind(k string) bool {
	switch k {
	case SessionHTTP, SessionHTTPJSP, SessionHTTPASPX, SessionReverse, SessionSSH:
		return true
	}
	return false
}

// SessionRecord 是 sessions 表的一行。Secret 在 Go 层是明文 JSON；Create 加密、
// Get/List 解密，密钥不出 SessionStore。
type SessionRecord struct {
	ID              int64     `json:"id"`
	TaskID          int64     `json:"task_id"`
	Kind            string    `json:"kind"` // http_php/http_jsp/http_aspx/reverse/ssh
	HostAssetID     int64     `json:"host_asset_id,omitempty"`
	CredentialID    int64     `json:"credential_id,omitempty"`
	URL             string    `json:"url"`
	Secret          string    `json:"secret"` // 明文 JSON；落库时加密
	Lang            string    `json:"lang"`
	Status          string    `json:"status"` // alive | dead
	CreatedByTask   int64     `json:"created_by_task,omitempty"`
	CreatedByIntent int64     `json:"created_by_intent,omitempty"`
	LastBeat        time.Time `json:"last_beat"`
	CreatedAt       time.Time `json:"created_at"`
}

// IsStale 判失联：alive 且 last_beat 距 now 超过 StaleAfter。
func (r *SessionRecord) IsStale(now time.Time) bool {
	if r == nil || r.Status != SessionAlive {
		return false
	}
	return now.Sub(r.LastBeat) > StaleAfter
}

// SessionSecretKey 由 master key（jwt.key 内容）派生会话加密密钥：
// SHA-256 域分离，与 JWT 签名、凭据库用途隔离。
func SessionSecretKey(master []byte) []byte {
	sum := sha256.Sum256(append([]byte("artex/sessions/v1\x00"), master...))
	return sum[:]
}

// SessionStore 是 sessions 表的访问层。key 为 32 字节 AES 密钥
// （经 SessionSecretKey 派生）；key 缺失时加解密直接报错（诚实失败，不落明文）。
type SessionStore struct {
	d   *DB
	key []byte
}

// NewSessionStore 构造访问层。masterKey 传 jwt.key 内容；内部自行派生。
func NewSessionStore(d *DB, masterKey []byte) *SessionStore {
	var key []byte
	if len(masterKey) > 0 {
		key = SessionSecretKey(masterKey)
	}
	return &SessionStore{d: d, key: key}
}

func (s *SessionStore) encrypt(plain string) (string, error) {
	if len(s.key) != 32 {
		return "", fmt.Errorf("会话加密密钥未初始化，拒绝明文落库")
	}
	gcm, err := newGCM(s.key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return secretPrefix + base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plain), nil)), nil
}

func (s *SessionStore) decrypt(stored string) (string, error) {
	if len(stored) == 0 {
		return "", nil
	}
	if len(s.key) != 32 {
		return "", fmt.Errorf("会话加密密钥未初始化，无法解密")
	}
	if !hasPrefix(stored, secretPrefix) {
		return "", fmt.Errorf("未知 secret 格式（缺 gcm1: 前缀），拒绝按明文读取")
	}
	raw, err := base64.StdEncoding.DecodeString(stored[len(secretPrefix):])
	if err != nil {
		return "", fmt.Errorf("secret base64 解码失败: %w", err)
	}
	gcm, err := newGCM(s.key)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("secret 密文过短")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("secret 解密失败（密钥不符或数据被篡改）: %w", err)
	}
	return string(plain), nil
}

// Create 插入一条会话并返回主键。Secret 加密存储；TaskID 为空时用 CreatedByTask 补。
func (s *SessionStore) Create(ctx context.Context, rec *SessionRecord) (int64, error) {
	if !ValidSessionKind(rec.Kind) {
		return 0, fmt.Errorf("非法会话类型 %q", rec.Kind)
	}
	enc, err := s.encrypt(rec.Secret)
	if err != nil {
		return 0, err
	}
	status := rec.Status
	if status == "" {
		status = SessionAlive
	}
	taskID := rec.TaskID
	if taskID == 0 {
		taskID = rec.CreatedByTask
	}
	var id int64
	err = s.d.QueryRowContext(ctx, `
INSERT INTO sessions(task_id, kind, host_asset_id, credential_id, url, secret, lang, status, created_by_task, created_by_intent)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING id`,
		taskID, rec.Kind, rec.HostAssetID, rec.CredentialID, rec.URL, enc, rec.Lang, status,
		nilIfZero(rec.CreatedByTask), nilIfZero(rec.CreatedByIntent)).Scan(&id)
	return id, err
}

const sessionCols = `id, task_id, kind, COALESCE(host_asset_id,0), COALESCE(credential_id,0), url, secret, lang, status,
	COALESCE(created_by_task,0), COALESCE(created_by_intent,0), last_beat, created_at`

func (s *SessionStore) scan(row interface{ Scan(...any) error }) (*SessionRecord, error) {
	var r SessionRecord
	var enc string
	if err := row.Scan(&r.ID, &r.TaskID, &r.Kind, &r.HostAssetID, &r.CredentialID, &r.URL, &enc, &r.Lang, &r.Status,
		&r.CreatedByTask, &r.CreatedByIntent, &r.LastBeat, &r.CreatedAt); err != nil {
		return nil, err
	}
	plain, err := s.decrypt(enc)
	if err != nil {
		return nil, fmt.Errorf("session %d: %w", r.ID, err)
	}
	r.Secret = plain
	return &r, nil
}

// Get 取一条（含解密 secret）；不存在返回 (nil, nil)。
func (s *SessionStore) Get(ctx context.Context, id int64) (*SessionRecord, error) {
	r, err := s.scan(s.d.QueryRowContext(ctx,
		`SELECT `+sessionCols+` FROM sessions WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

// ListByTask 取某任务的全部会话（按 id 升序）；status 非空时按状态过滤。
func (s *SessionStore) ListByTask(ctx context.Context, taskID int64, status string) ([]*SessionRecord, error) {
	query := `SELECT ` + sessionCols + ` FROM sessions WHERE task_id=$1`
	args := []any{taskID}
	if status != "" {
		query += ` AND status=$2`
		args = append(args, status)
	}
	query += ` ORDER BY id`
	rows, err := s.d.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*SessionRecord{}
	for rows.Next() {
		r, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateStatus 更新 alive/dead 状态。
func (s *SessionStore) UpdateStatus(ctx context.Context, id int64, status string) error {
	if status != SessionAlive && status != SessionDead {
		return fmt.Errorf("非法会话状态 %q（alive|dead）", status)
	}
	_, err := s.d.ExecContext(ctx, `UPDATE sessions SET status=$2 WHERE id=$1`, id, status)
	return err
}

// Touch 刷新 last_beat（每次使用会话时调用）。
func (s *SessionStore) Touch(ctx context.Context, id int64) {
	_, _ = s.d.ExecContext(ctx, `UPDATE sessions SET last_beat=now() WHERE id=$1`, id)
}

// SetHostAsset 回填会话关联的立足点主机资产 id。
func (s *SessionStore) SetHostAsset(ctx context.Context, id, assetID int64) {
	_, _ = s.d.ExecContext(ctx, `UPDATE sessions SET host_asset_id=$2 WHERE id=$1`, id, assetID)
}

// Delete 删除一条会话。
func (s *SessionStore) Delete(ctx context.Context, id int64) error {
	_, err := s.d.ExecContext(ctx, `DELETE FROM sessions WHERE id=$1`, id)
	return err
}

// SaveReconReport 保存一次 session_recon 被动侦察报告（report 为 JSON)。
func (s *SessionStore) SaveReconReport(ctx context.Context, taskID, sessionID int64, report json.RawMessage) (int64, error) {
	var id int64
	err := s.d.QueryRowContext(ctx,
		`INSERT INTO session_recon_reports (task_id, session_id, report) VALUES ($1,$2,$3) RETURNING id`,
		taskID, sessionID, report).Scan(&id)
	return id, err
}

// ListReconReports 按时间倒序取某会话的侦察报告（最新在前，默认取全部）。
func (s *SessionStore) ListReconReports(ctx context.Context, sessionID int64) ([]json.RawMessage, error) {
	rows, err := s.d.QueryContext(ctx,
		`SELECT report FROM session_recon_reports WHERE session_id=$1 ORDER BY id DESC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var r json.RawMessage
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
