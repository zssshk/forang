// sessions.go 是立足点会话的 HTTP 层（v0.6.5)：会话登记/列表/详情/心跳/
// exec/read/write/删除 + reverse_listen 接管同步 + 侦察报告查看。全部挂在
// /api/tasks/{id}/… 下，走默认 JWT 鉴权。
//
// 安全边界：会话 secret 只进不出——列表与详情一律剥离 Secret 字段，只给
// 元数据 + stale 标记；入库走 AES-GCM（密钥由 jwt.key 派生），未配密钥时
// 创建接口直接 503，绝不明文落库；webshell 明文通道须显式 allow_plaintext。
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
	"github.com/Autumn-27/artex/tunnel"
)

// sessionStore 构造会话库（AES-GCM，密钥由 jwt.key 派生）。
func (s *Server) sessionStore() *db.SessionStore {
	return db.NewSessionStore(s.m.PG(), s.jwtKey)
}

// stripSessionSecret 把会话记录剥离 secret 后返回（只给元数据 + 失联标记）。
func stripSessionSecret(c *db.SessionRecord) map[string]any {
	return map[string]any{
		"id": c.ID, "task_id": c.TaskID, "kind": c.Kind,
		"host_asset_id": c.HostAssetID, "credential_id": c.CredentialID,
		"url": c.URL, "lang": c.Lang, "status": c.Status,
		"last_beat": c.LastBeat.Format(time.RFC3339),
		"stale":     c.IsStale(time.Now()),
	}
}

// lookupSession 按 id 取会话驱动：先查进程内注册表，未命中则从库加载并建驱动。
func (s *Server) lookupSession(ctx context.Context, taskID, sessionID int64) (session.Session, *db.SessionRecord, error) {
	if drv, ok := s.sessRegistry.Get(sessionID); ok {
		rec, err := s.sessionStore().Get(ctx, sessionID)
		if err != nil {
			return nil, nil, err
		}
		if rec == nil || (taskID != 0 && rec.TaskID != taskID) {
			return nil, nil, session.ErrSessionNotFound
		}
		return drv, rec, nil
	}
	rec, err := s.sessionStore().Get(ctx, sessionID)
	if err != nil {
		return nil, nil, err
	}
	if rec == nil || (taskID != 0 && rec.TaskID != taskID) {
		return nil, nil, session.ErrSessionNotFound
	}
	drv, err := session.DriverFor(rec, s.penelopeCaller())
	if err != nil {
		return nil, rec, err
	}
	s.sessRegistry.Add(drv)
	return drv, rec, nil
}

// penelopeCaller 返回当前 penelope MCP 调用器（handler 未启动时为 nil)。
func (s *Server) penelopeCaller() session.MCPCaller {
	if s.reverseMgr == nil {
		return nil
	}
	return s.reverseMgr.Caller()
}

// listSessions 列出本任务的立足点会话（只给元数据）。
func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	status := r.URL.Query().Get("status")
	rows, err := s.sessionStore().ListByTask(r.Context(), taskID, status)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	meta := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		meta = append(meta, stripSessionSecret(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"task_id": taskID, "sessions": meta})
}

// createSession 登记一个立足点会话；登记后立即 Test，不通记 dead 并如实返回。
func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	var req struct {
		Kind           string `json:"kind"`
		URL            string `json:"url"`
		Password       string `json:"password"`
		Encoder        string `json:"encoder"`
		ScriptType     string `json:"script_type"`
		AllowPlaintext bool   `json:"allow_plaintext"`
		PenSessionID   int64  `json:"pen_session_id"`
		HostAssetID    int64  `json:"host_asset_id"`
		CredentialID   int64  `json:"credential_id"`
		Lang           string `json:"lang"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if len(s.jwtKey) == 0 {
		writeErr(w, http.StatusServiceUnavailable, "会话加密主钥未配置（jwt.key)，拒绝明文落库")
		return
	}
	secret, err := buildSessionSecret(req.Kind, req.URL, req.Password, req.Encoder, req.ScriptType, req.AllowPlaintext, req.PenSessionID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	st := s.sessionStore()
	rec := &db.SessionRecord{
		TaskID: taskID, Kind: req.Kind, HostAssetID: req.HostAssetID,
		CredentialID: req.CredentialID, URL: req.URL, Secret: string(secret),
		Lang: req.Lang, Status: db.SessionAlive, CreatedByTask: taskID,
	}
	id, err := st.Create(r.Context(), rec)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	drv, _, derr := s.lookupSession(r.Context(), taskID, id)
	if derr != nil {
		_ = st.UpdateStatus(r.Context(), id, db.SessionDead)
		writeJSON(w, http.StatusCreated, map[string]any{
			"session": stripSessionSecret(mustGetSession(r.Context(), st, id)),
			"error":   "会话已登记但驱动不可用：" + derr.Error(),
		})
		return
	}
	tctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := drv.Test(tctx); err != nil {
		_ = st.UpdateStatus(r.Context(), id, db.SessionDead)
		writeJSON(w, http.StatusCreated, map[string]any{
			"session": stripSessionSecret(mustGetSession(r.Context(), st, id)),
			"error":   "会话已登记但连通测试失败：" + err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"session": stripSessionSecret(mustGetSession(r.Context(), st, id)), "tested": true,
	})
}

// buildSessionSecret 按 kind 组装会话 secret JSON（与 agent 侧同逻辑；
// 明文口令只在此处出现，调用方 Create 即加密落库；出参绝不回显）。
func buildSessionSecret(kind, url, password, encoder, scriptType string, allowPlaintext bool, penSessionID int64) (json.RawMessage, error) {
	switch kind {
	case db.SessionHTTP, db.SessionHTTPJSP, db.SessionHTTPASPX:
		if strings.TrimSpace(url) == "" {
			return nil, fmt.Errorf("http 类会话须给 url")
		}
		if encoder == "" {
			encoder = "aes"
		}
		if (encoder == "aes" || encoder == "xor") && password == "" {
			return nil, fmt.Errorf("encoder=%s 须给 password（明文通道须显式 allow_plaintext=true，且不建议）", encoder)
		}
		if encoder == "raw" && !allowPlaintext {
			return nil, fmt.Errorf("encoder=raw 是明文通道：须显式 allow_plaintext=true 才登记（生产勿开）")
		}
		b, _ := json.Marshal(map[string]any{
			"password": password, "encoder": encoder, "script_type": scriptType,
			"allow_plaintext": allowPlaintext,
		})
		return b, nil
	case db.SessionReverse:
		if penSessionID <= 0 {
			return nil, fmt.Errorf("reverse 类会话须给 pen_session_id（先 reverse_listen 同步）")
		}
		b, _ := json.Marshal(map[string]any{"pen_session_id": penSessionID})
		return b, nil
	case db.SessionSSH:
		return nil, fmt.Errorf("ssh 会话暂无驱动（仅登记无意义）：先用 http/reverse 立足点")
	default:
		return nil, fmt.Errorf("未知会话类型 %q", kind)
	}
}

func mustGetSession(ctx context.Context, st *db.SessionStore, id int64) *db.SessionRecord {
	rec, _ := st.Get(ctx, id)
	if rec == nil {
		return &db.SessionRecord{ID: id}
	}
	return rec
}

// getSession 取单个会话详情（只给元数据）。
func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	sid, err := strconv.ParseInt(r.PathValue("sid"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad session id")
		return
	}
	rec, err := s.sessionStore().Get(r.Context(), sid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rec == nil || rec.TaskID != taskID {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": stripSessionSecret(rec)})
}

// heartbeatSession 刷新会话心跳（last_beat=now），返回最新元数据。
func (s *Server) heartbeatSession(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	sid, err := strconv.ParseInt(r.PathValue("sid"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad session id")
		return
	}
	st := s.sessionStore()
	rec, err := st.Get(r.Context(), sid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rec == nil || rec.TaskID != taskID {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	st.Touch(r.Context(), sid)
	writeJSON(w, http.StatusOK, map[string]any{"session": stripSessionSecret(mustGetSession(r.Context(), st, sid))})
}

// execSession 经会话执行一条命令。
func (s *Server) execSession(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	sid, err := strconv.ParseInt(r.PathValue("sid"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad session id")
		return
	}
	var req struct {
		Cmd        string `json:"cmd"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	drv, _, err := s.lookupSession(r.Context(), taskID, sid)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	to := time.Duration(req.TimeoutSec) * time.Second
	if to <= 0 {
		to = 60 * time.Second
	}
	if to > 300*time.Second {
		to = 300 * time.Second
	}
	stdout, stderr, err := drv.Exec(r.Context(), req.Cmd, to)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.sessionStore().Touch(r.Context(), sid)
	writeJSON(w, http.StatusOK, map[string]any{"session_id": sid, "stdout": stdout, "stderr": stderr})
}

// readSessionFile 经会话读目标侧一个文件（base64 返回）。
func (s *Server) readSessionFile(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	sid, err := strconv.ParseInt(r.PathValue("sid"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad session id")
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	drv, _, err := s.lookupSession(r.Context(), taskID, sid)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	data, err := drv.ReadFile(r.Context(), req.Path)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.sessionStore().Touch(r.Context(), sid)
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": sid, "path": req.Path, "size": len(data),
		"data_base64": base64.StdEncoding.EncodeToString(data),
	})
}

// writeSessionFile 经会话写目标侧一个文件。
func (s *Server) writeSessionFile(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	sid, err := strconv.ParseInt(r.PathValue("sid"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad session id")
		return
	}
	var req struct {
		Path       string `json:"path"`
		DataBase64 string `json:"data_base64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.DataBase64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "data_base64 解码失败: "+err.Error())
		return
	}
	drv, _, err := s.lookupSession(r.Context(), taskID, sid)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err := drv.WriteFile(r.Context(), req.Path, data); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.sessionStore().Touch(r.Context(), sid)
	writeJSON(w, http.StatusOK, map[string]any{"session_id": sid, "path": req.Path, "size": len(data), "written": true})
}

// deleteSession 删除会话（注册表驱逐 + 库删除；reverse 会话的远端 shell
// 不在此处 kill——远端会话由 penelope 侧 kill_session 显式处理）。
func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	sid, err := strconv.ParseInt(r.PathValue("sid"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad session id")
		return
	}
	st := s.sessionStore()
	rec, err := st.Get(r.Context(), sid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rec == nil || rec.TaskID != taskID {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	s.sessRegistry.Remove(sid)
	if err := st.Delete(r.Context(), sid); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "session_id": sid})
}

// reverseListen 启动/复用 penelope 接管端，并把已连上的反弹会话同步登记。
func (s *Server) reverseListen(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	var req struct {
		Port int `json:"port"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if s.reverseMgr == nil {
		writeErr(w, http.StatusServiceUnavailable, "penelope 未配置（未设 ARTEX_PENELOPE_BIN 或 ARTEX_PENELOPE_MCP_URL)，无法接管反弹 shell")
		return
	}
	if err := s.reverseMgr.Start(r.Context(), req.Port); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	caller := s.reverseMgr.Caller()
	if caller == nil {
		writeErr(w, http.StatusBadGateway, "penelope 接管端未就绪（MCP 握手失败）")
		return
	}
	st := s.sessionStore()
	penSessions, err := session.ListPenelopeSessions(r.Context(), caller)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "列 penelope 会话失败: "+err.Error())
		return
	}
	existing, _ := st.ListByTask(r.Context(), taskID, "")
	known := map[int64]bool{}
	for _, rec := range existing {
		if rec.Kind != db.SessionReverse {
			continue
		}
		var sec struct {
			PenSessionID int64 `json:"pen_session_id"`
		}
		if json.Unmarshal([]byte(rec.Secret), &sec) == nil && sec.PenSessionID > 0 {
			known[sec.PenSessionID] = true
		}
	}
	synced := []int64{}
	for _, ps := range penSessions {
		if known[int64(ps.ID)] {
			continue
		}
		sec, _ := json.Marshal(map[string]any{
			"pen_session_id": ps.ID,
			"mcp_url":        s.reverseMgr.MCPURL(),
			"token":          s.reverseMgr.Token(),
		})
		rec := &db.SessionRecord{
			TaskID: taskID, Kind: db.SessionReverse, Secret: string(sec),
			Status: db.SessionAlive, CreatedByTask: taskID, Lang: ps.OS,
		}
		id, err := st.Create(r.Context(), rec)
		if err != nil {
			continue
		}
		synced = append(synced, id)
	}
	portOut := req.Port
	if portOut <= 0 {
		portOut = 4444
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"listening": true, "port": portOut,
		"penelope_sessions": len(penSessions), "synced_new": synced,
	})
}

// listSessionReconReports 列出某会话的被动侦察报告（最新在前）。
func (s *Server) listSessionReconReports(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	sid, err := strconv.ParseInt(r.PathValue("sid"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad session id")
		return
	}
	rec, err := s.sessionStore().Get(r.Context(), sid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rec == nil || rec.TaskID != taskID {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	reports, err := s.sessionStore().ListReconReports(r.Context(), sid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session_id": sid, "reports": reports})
}

// initSessionSubsystem 装配立足点会话子系统（Server 构造时调用一次）：
// 进程内会话注册表 + penelope handler + 隧道部署管理器。二进制/目录缺失时
// Manager 只记日志、对应部署报明确错误，不阻断启动。
func (s *Server) initSessionSubsystem() {
	s.sessRegistry = session.NewRegistry()
	s.reverseMgr = session.NewReverseManager(
		os.Getenv("ARTEX_PENELOPE_BIN"),
		os.Getenv("ARTEX_PENELOPE_MCP_URL"),
	)
	chiselPath := os.Getenv("ARTEX_CHISEL_PATH")
	if chiselPath == "" {
		if p := filepath.Join(s.m.dir, "tools", "chisel"); fileExists(p) {
			chiselPath = p
		}
	}
	suo5Path := os.Getenv("ARTEX_SUO5_PATH")
	if suo5Path == "" {
		if p := filepath.Join(s.m.dir, "tools", "suo5"); fileExists(p) {
			suo5Path = p
		}
	}
	suo5PayloadsDir := os.Getenv("ARTEX_SUO5_PAYLOADS_DIR")
	if suo5PayloadsDir == "" {
		if p := filepath.Join(s.m.dir, "tools", "suo5-payloads"); dirExists(p) {
			suo5PayloadsDir = p
		}
	}
	mgr, err := tunnel.NewManager(tunnel.Options{
		Store:           db.NewTunnelStore(s.m.PG()),
		Sessions:        s.sessRegistry,
		ChiselPath:      chiselPath,
		Suo5Path:        suo5Path,
		Suo5PayloadsDir: suo5PayloadsDir,
		DataDir:         s.m.dir,
	})
	if err != nil {
		log.Printf("[sessions] tunnel manager 装配失败： %v —— tunnel_deploy 不可用", err)
		return
	}
	mgr.OnAttempt = func(tunnelID, sessionID int64, adapter, status, detail string) {
		if err := db.NewTunnelStore(s.m.PG()).RecordDeployAttempt(
			context.Background(), tunnelID, sessionID, adapter, status, detail); err != nil {
			log.Printf("[sessions] 投递尝试落库失败（tunnel=%d): %v", tunnelID, err)
		}
	}
	s.tunnelMgr = mgr
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
