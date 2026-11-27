// tunnel_deploy.go 是隧道远端投递的 HTTP 层（v0.6.5)：
// POST /api/tasks/{id}/tunnels/{tid}/deploy —— 把已建计划的隧道投递到立足点
// 远端并拉起（chisel / suo5，复用 tunnel.Manager）；
// GET /api/tasks/{id}/tunnels/{tid}/attempts —— 投递尝试记录。
//
// 纪律：只对 deploying/error 的台账行部署（error 即重试）；只有隧道内决定性
// 验证通过才标 alive；失败时台账标 error 并记一条尝试，不删台账行。
package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/tunnel"
)

// mustPlan 从台账行解析部署计划（解析失败返回空计划，入口地址为空串）。
func mustPlan(rec *db.TunnelRecord) *tunnel.Plan {
	var p tunnel.Plan
	if err := json.Unmarshal(rec.DeployParams, &p); err != nil {
		return &tunnel.Plan{}
	}
	return &p
}

// deployTunnel 执行一次远端投递。
func (s *Server) deployTunnel(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	tid, err := strconv.ParseInt(r.PathValue("tid"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad tunnel id")
		return
	}
	if s.tunnelMgr == nil {
		writeErr(w, http.StatusServiceUnavailable, "隧道部署不可用（tunnel manager 未装配）")
		return
	}
	var req struct {
		SessionID int64 `json:"session_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	ts := db.NewTunnelStore(s.m.PG())
	rec, err := ts.Get(r.Context(), tid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rec == nil || rec.TaskID != taskID {
		writeErr(w, http.StatusNotFound, "tunnel not found")
		return
	}
	if rec.State != db.TunnelDeploying && rec.State != db.TunnelError {
		writeErr(w, http.StatusBadRequest, "隧道当前状态 "+rec.State+"，不可部署（仅 deploying/error 可部署/重试）")
		return
	}
	sessID := req.SessionID
	if sessID <= 0 {
		sessID = rec.ViaSessionID
	}
	if sessID <= 0 {
		writeErr(w, http.StatusBadRequest, "隧道未指定经哪个立足点部署（计划缺 via_session_id)")
		return
	}
	drv, _, err := s.lookupSession(r.Context(), taskID, sessID)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err := s.tunnelMgr.DeployExisting(r.Context(), rec, drv); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.sessionStore().Touch(r.Context(), sessID)
	rec, _ = ts.Get(r.Context(), tid)
	writeJSON(w, http.StatusOK, map[string]any{
		"tunnel_id": rec.ID, "state": rec.State,
		"adapter": rec.Adapter, "kind": rec.Kind,
		"entry": s.tunnelMgr.EntryAddr(mustPlan(rec)),
	})
}

// listTunnelAttempts 列出某隧道的投递尝试（最新在前）。
func (s *Server) listTunnelAttempts(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	tid, err := strconv.ParseInt(r.PathValue("tid"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad tunnel id")
		return
	}
	ts := db.NewTunnelStore(s.m.PG())
	rec, err := ts.Get(r.Context(), tid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rec == nil || rec.TaskID != taskID {
		writeErr(w, http.StatusNotFound, "tunnel not found")
		return
	}
	rows, err := ts.ListDeployAttempts(r.Context(), tid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tunnel_id": tid, "attempts": rows})
}
