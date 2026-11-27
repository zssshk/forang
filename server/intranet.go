// intranet.go 是 v0.6.3 artex-ymh 移植的内网作战 HTTP 层：凭据库 / 隧道台账 /
// 待授权网段 / 外网→内网任务移交 / 内网拓扑图。全部挂在 /api/tasks/{id}/…
// 下，走默认 JWT 鉴权。
//
// 安全边界：凭据 secret 只进不出——列表与详情一律剥离 Secret 字段；入库走
// AES-GCM（密钥由 jwt.key 派生），未配密钥时创建接口直接 503，绝不明文落库。
// 隧道 plan 只生成 + 入账（state=deploying）；远端投递走立足点会话子系统
// （v0.6.5：POST /api/tasks/{id}/tunnels/{tid}/deploy），只有决定性验证
// 通过才标 alive，不谎报。
package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/tunnel"
)

// intranetTask 解析任务 + 取资产库；失败直接写错误响应。
func (s *Server) intranetTask(w http.ResponseWriter, r *http.Request) (*Task, *db.AssetStore, int64, bool) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return nil, nil, 0, false
	}
	as := s.m.Assets()
	if as == nil {
		writeErr(w, http.StatusServiceUnavailable, "asset store 未启用")
		return nil, nil, 0, false
	}
	taskID, err := parseTaskID(t.ID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return nil, nil, 0, false
	}
	return t, as, taskID, true
}

// credentialStore 构造凭据库（AES-GCM，密钥由 jwt.key 派生）。
func (s *Server) credentialStore() *db.CredentialStore {
	return db.NewCredentialStore(s.m.PG(), s.jwtKey)
}

// stripCredentialSecret 把凭据记录剥离 secret 后返回（只给元数据）。
func stripCredentialSecret(c *db.CredentialRecord) map[string]any {
	return map[string]any{
		"id": c.ID, "task_id": c.TaskID, "host_asset_id": c.HostAssetID,
		"username": c.Username, "cred_type": c.CredType, "domain": c.Domain,
		"source": c.Source, "verified": c.Verified, "created_at": c.CreatedAt,
	}
}

// intranetOverview 是内网作战总览：凭据数、隧道、待授权网段、疑似蜜罐、拓扑图。
func (s *Server) intranetOverview(w http.ResponseWriter, r *http.Request) {
	_, as, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	out := map[string]any{"task_id": taskID}
	if creds, err := s.credentialStore().ListByTask(ctx, taskID); err == nil {
		meta := make([]map[string]any, 0, len(creds))
		for _, c := range creds {
			meta = append(meta, stripCredentialSecret(c))
		}
		out["credentials"] = meta
	}
	tun := db.NewTunnelStore(s.m.PG())
	if rows, err := tun.ListByTask(ctx, taskID); err == nil {
		out["tunnels"] = rows
	}
	if rows, err := s.sessionStore().ListByTask(ctx, taskID, ""); err == nil {
		meta := make([]map[string]any, 0, len(rows))
		for _, c := range rows {
			meta = append(meta, stripSessionSecret(c))
		}
		out["sessions"] = meta
	}
	if rows, err := as.ListPendingScope(taskID, true); err == nil {
		out["pending_scope"] = rows
	}
	if rows, err := as.HoneypotAssetsByTask(taskID, 20); err == nil {
		out["honeypot_assets"] = rows
	}
	nodes, edges := s.intranetTopology(as, taskID)
	out["topology"] = map[string]any{"nodes": nodes, "edges": edges}
	writeJSON(w, http.StatusOK, out)
}

// intranetTopology 从任务资产建内网拓扑图（按任务过滤）：节点 = 主机（ip 资产）
// + 服务（service 资产），边 = 主机→服务（同 IP）与同网段主机互联。
// 蜜罐资产打 honeypot 标记。best-effort，查不到返回空图。
func (s *Server) intranetTopology(as *db.AssetStore, taskID int64) ([]map[string]any, []map[string]any) {
	nodes := []map[string]any{}
	edges := []map[string]any{}
	assets, err := as.QueryDSLInScope("", "", taskID, 500, 0)
	if err != nil {
		return nodes, edges
	}
	honey := map[int64]bool{}
	if rows, err := as.HoneypotAssetsByTask(taskID, 100); err == nil {
		for _, h := range rows {
			honey[h.ID] = true
		}
	}
	hostByIP := map[string]int64{}
	segHosts := map[string][]int64{}
	for _, a := range assets {
		switch a.Type {
		case "ip":
			if a.IP == "" {
				continue
			}
			hostByIP[a.IP] = a.ID
			if a.CSegment != "" {
				segHosts[a.CSegment] = append(segHosts[a.CSegment], a.ID)
			}
			nodes = append(nodes, map[string]any{
				"id": a.ID, "kind": "host", "ip": a.IP, "segment": a.CSegment,
				"honeypot": honey[a.ID],
			})
		case "service":
			ip := a.IP
			if ip == "" && a.URL != "" {
				if u, err := parseURLHost(a.URL); err == nil {
					ip = u
				}
			}
			label := a.ServiceName
			if label == "" {
				label = a.URL
			}
			nodes = append(nodes, map[string]any{
				"id": a.ID, "kind": "service", "label": label, "ip": ip,
				"port": a.Port, "honeypot": honey[a.ID],
			})
			if hid, ok := hostByIP[ip]; ok && ip != "" {
				edges = append(edges, map[string]any{"from": hid, "to": a.ID, "type": "runs"})
			}
		}
	}
	// 同网段主机互联（只连相邻两台，避免全连接爆炸）。
	for _, ids := range segHosts {
		for i := 1; i < len(ids); i++ {
			edges = append(edges, map[string]any{"from": ids[i-1], "to": ids[i], "type": "same_segment"})
		}
	}
	return nodes, edges
}

func parseURLHost(raw string) (string, error) {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}

// listCredentials 列出本任务凭据（只给元数据，secret 永不返回）。
func (s *Server) listCredentials(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	creds, err := s.credentialStore().ListByTask(r.Context(), taskID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	meta := make([]map[string]any, 0, len(creds))
	for _, c := range creds {
		meta = append(meta, stripCredentialSecret(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": meta})
}

// createCredential 登记一条凭据（加密入库）。
func (s *Server) createCredential(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	var req struct {
		Username    string `json:"username"`
		CredType    string `json:"cred_type"`
		Secret      string `json:"secret"`
		Domain      string `json:"domain"`
		Source      string `json:"source"`
		HostAssetID int64  `json:"host_asset_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if !db.ValidCredType(req.CredType) {
		writeErr(w, http.StatusBadRequest, "非法 cred_type "+strconv.Quote(req.CredType))
		return
	}
	if strings.TrimSpace(req.Secret) == "" {
		writeErr(w, http.StatusBadRequest, "secret 不能为空")
		return
	}
	id, err := s.credentialStore().Create(r.Context(), &db.CredentialRecord{
		TaskID: taskID, HostAssetID: req.HostAssetID,
		Username: req.Username, CredType: req.CredType, Secret: req.Secret,
		Domain: req.Domain, Source: req.Source,
	})
	if err != nil {
		// 密钥未初始化时 Create 直接报错（诚实失败，不落明文）。
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"credential_id": id, "encrypted": true})
}

// deleteCredential 删除一条凭据。
func (s *Server) deleteCredential(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	cid, err := strconv.ParseInt(r.PathValue("cid"), 10, 64)
	if err != nil || cid <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid credential id")
		return
	}
	// 归属校验：只能删本任务的凭据。
	if rec, err := s.credentialStore().Get(r.Context(), cid); err != nil || rec.TaskID != taskID {
		writeErr(w, http.StatusNotFound, "credential not found")
		return
	}
	if err := s.credentialStore().Delete(r.Context(), cid); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": cid})
}

// verifyCredential 标记一条凭据是否已实测可用（实测本身由 agent/人工做，
// 这里只记结论；verified=true 的凭据在复用打分里 +25）。
func (s *Server) verifyCredential(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	cid, err := strconv.ParseInt(r.PathValue("cid"), 10, 64)
	if err != nil || cid <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid credential id")
		return
	}
	var req struct {
		Verified bool `json:"verified"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if rec, err := s.credentialStore().Get(r.Context(), cid); err != nil || rec.TaskID != taskID {
		writeErr(w, http.StatusNotFound, "credential not found")
		return
	}
	if err := s.credentialStore().SetVerified(r.Context(), cid, req.Verified); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credential_id": cid, "verified": req.Verified})
}

// listTunnels 列出本任务隧道台账。
func (s *Server) listTunnels(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	rows, err := db.NewTunnelStore(s.m.PG()).ListByTask(r.Context(), taskID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tunnels": rows})
}

// createTunnelPlan 生成一条隧道计划并入账（state=deploying；投递走 tunnel_deploy 接口，见 server/tunnel_deploy.go）。
func (s *Server) createTunnelPlan(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	var req struct {
		Kind        string `json:"kind"`
		TCPOut      bool   `json:"tcp_out"`
		WebshellURL string `json:"webshell_url"`
		TargetHost  string `json:"target_host"`
		TargetPort  int    `json:"target_port"`
		VerifyAddr  string `json:"verify_addr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	adapter, reason, err := tunnel.SelectAdapter(req.Kind, tunnel.ProbeResult{TCPOut: req.TCPOut, WebshellURL: req.WebshellURL})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "隧道选型失败: "+err.Error())
		return
	}
	callback := strings.TrimSpace(os.Getenv("ARTEX_CALLBACK_ADDR"))
	if callback == "" {
		writeErr(w, http.StatusBadRequest, "回连地址未配置：部署环境须设置 ARTEX_CALLBACK_ADDR")
		return
	}
	callbackHost, _, err := net.SplitHostPort(callback)
	if err != nil {
		callbackHost = callback
	}
	min, max, err := tunnel.ParsePortRange(os.Getenv("ARTEX_TUNNEL_PORT_RANGE"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "端口池非法: "+err.Error())
		return
	}
	ctx := r.Context()
	used := map[int]bool{}
	tun := db.NewTunnelStore(s.m.PG())
	if alive, err := tun.ListActive(ctx); err == nil {
		for _, rec := range alive {
			used[rec.ListenPort] = true
		}
	}
	dataDir := filepath.Join(s.m.dir, "tunnels")
	_ = os.MkdirAll(dataDir, 0o700)
	opts := &tunnel.PlanOpts{
		TaskID: taskID, Adapter: adapter,
		CallbackHost: callbackHost, VerifyAddr: req.VerifyAddr,
		PortMin: min, PortMax: max, UsedPorts: used,
		CanListen: func(port int) bool {
			ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
			if err != nil {
				return false
			}
			_ = ln.Close()
			return true
		},
		DataDir: dataDir,
	}
	var plan *tunnel.Plan
	if req.Kind == tunnel.KindSocks {
		plan, err = tunnel.PlanSocks(opts)
	} else {
		opts.TargetHost, opts.TargetPort = req.TargetHost, req.TargetPort
		plan, err = tunnel.PlanPortfwd(opts)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "隧道计划生成失败: "+err.Error())
		return
	}
	raw, _ := json.Marshal(plan)
	tunnelID, err := tun.Create(ctx, &db.TunnelRecord{
		TaskID: taskID, Kind: req.Kind, Adapter: adapter,
		ListenHost: plan.ListenHost, ListenPort: plan.ListenPort,
		TargetHost: req.TargetHost, TargetPort: req.TargetPort,
		DeployParams: raw, State: db.TunnelDeploying,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]any{
		"tunnel_id": tunnelID, "adapter": adapter, "selection_reason": reason,
		"listen": fmt.Sprintf("%s:%d", plan.ListenHost, plan.ListenPort),
		"state":  db.TunnelDeploying,
		"note":   "计划已生成并入账；远端投递走 tunnel_deploy 接口（需立足点会话），当前 state 保持 deploying，不谎报 alive",
	}
	if req.Kind == tunnel.KindSocks {
		out["socks_entry"] = fmt.Sprintf("socks5://127.0.0.1:%d", plan.SocksPort)
	} else {
		out["local_entry"] = fmt.Sprintf("127.0.0.1:%d -> %s:%d", plan.LocalPort, req.TargetHost, req.TargetPort)
	}
	writeJSON(w, http.StatusCreated, out)
}

// updateTunnelState 更新一条隧道的状态（alive/error/stopped；deploying 只能由
// 部署流程推进，这里不接受人工直接标 alive——决定性验证未通过不许谎报）。
func (s *Server) updateTunnelState(w http.ResponseWriter, r *http.Request) {
	_, _, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	tid, err := strconv.ParseInt(r.PathValue("tid"), 10, 64)
	if err != nil || tid <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid tunnel id")
		return
	}
	var req struct {
		State string `json:"state"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	switch req.State {
	case db.TunnelAlive, db.TunnelError, db.TunnelStopped:
	default:
		writeErr(w, http.StatusBadRequest, "state 只接受 alive/error/stopped（deploying 由部署流程推进）")
		return
	}
	tun := db.NewTunnelStore(s.m.PG())
	if rec, err := tun.Get(r.Context(), tid); err != nil || rec.TaskID != taskID {
		writeErr(w, http.StatusNotFound, "tunnel not found")
		return
	}
	if err := tun.UpdateState(r.Context(), tid, req.State, req.Error); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tunnel_id": tid, "state": req.State})
}

// listPendingScope 列出本任务待授权网段（默认只给 pending；?all=1 给全部）。
func (s *Server) listPendingScope(w http.ResponseWriter, r *http.Request) {
	_, as, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	rows, err := as.ListPendingScope(taskID, r.URL.Query().Get("all") == "1")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pending_scope": rows})
}

// createPendingScope 登记一条待授权网段（agent/人工都可调；幂等，重复只累计 hits）。
func (s *Server) createPendingScope(w http.ResponseWriter, r *http.Request) {
	_, as, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	var req struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if req.Kind == "" {
		req.Kind = "cidr"
	}
	created, err := as.UpsertPendingScope(taskID, req.Kind, strings.TrimSpace(req.Value))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"created": created, "kind": req.Kind, "value": req.Value})
}

// decidePendingScope 人工批准/拒绝一条待授权网段。批准后写进 task_scope 扩范围。
func (s *Server) decidePendingScope(w http.ResponseWriter, r *http.Request) {
	_, as, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	sid, err := strconv.ParseInt(r.PathValue("sid"), 10, 64)
	if err != nil || sid <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid pending scope id")
		return
	}
	var req struct {
		Approved bool `json:"approved"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	rec, err := as.GetPendingScope(sid)
	if err != nil || rec.TaskID != taskID {
		writeErr(w, http.StatusNotFound, "pending scope not found")
		return
	}
	decided, err := as.DecidePendingScope(sid, req.Approved)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.Approved {
		// 批准即扩范围：kind cidr/ip 直接进 task_scope。
		if _, err := as.AddAgentScope(taskID, rec.Kind, rec.Value, "pending_scope 人工批准", "human"); err != nil {
			writeErr(w, http.StatusInternalServerError, "批准已记、扩范围失败: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, decided)
}

// createHandoff 是外网→内网任务移交：以一个立足点主机资产建子任务，初始范围
// 只有该主机 /32；新网段须走 pending_scope 人工批准，子任务描述里写明纪律。
func (s *Server) createHandoff(w http.ResponseWriter, r *http.Request) {
	t, as, taskID, ok := s.intranetTask(w, r)
	if !ok {
		return
	}
	var req struct {
		AssetID int64  `json:"asset_id"`
		Note    string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	assets, err := as.GetByIDs([]int64{req.AssetID})
	if err != nil || len(assets) == 0 {
		writeErr(w, http.StatusNotFound, "foothold asset not found")
		return
	}
	host := assets[0]
	if host.IP == "" {
		writeErr(w, http.StatusBadRequest, "立足点资产没有 IP，无法限定 /32 范围")
		return
	}
	goal := fmt.Sprintf("内网横向：以立足点 %s 为起点扩散。纪律：初始范围只有该主机 /32；发现新网段先登记 pending_scope、等人工批准再扩范围；凭据复用先查凭据库打分；疑似蜜罐只降级交互。", host.IP)
	if strings.TrimSpace(req.Note) != "" {
		goal += "\n移交说明：" + strings.TrimSpace(req.Note)
	}
	sub, err := s.m.CreateTaskWithOptions(
		fmt.Sprintf("内网移交（源任务 #%d，立足点 %s）", taskID, host.IP),
		goal,
		db.TaskCreateOptions{SourceTaskIDs: []int64{taskID}},
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	subID, _ := parseTaskID(sub.ID)
	// 初始范围：只有立足点主机 /32。
	if _, err := as.AddAgentScope(subID, "ip", host.IP, "handoff 立足点初始范围", "handoff"); err != nil {
		writeErr(w, http.StatusInternalServerError, "子任务已建、初始范围写入失败: "+err.Error())
		return
	}
	if _, err := as.AttachAssetsToTask(subID, []int64{req.AssetID}, "handoff 立足点"); err != nil {
		writeErr(w, http.StatusInternalServerError, "子任务已建、立足点挂接失败: "+err.Error())
		return
	}
	_ = t // 源任务句柄（预留：后续可在此记移交审计）
	s.launchTask(sub, goal, true)
	writeJSON(w, http.StatusCreated, map[string]any{
		"subtask_id": sub.ID, "foothold": host.IP,
		"scope": host.IP + "/32",
		"note":  "子任务已启动；新网段须走 pending_scope 人工批准",
	})
}
