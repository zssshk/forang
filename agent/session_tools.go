// session_tools.go 是立足点会话的 agent 工具层（v0.6.5，artex-ymh 移植）：
// register_session / session_exec / session_read / session_write /
// reverse_listen / session_recon / tunnel_deploy。
//
// 安全纪律：
// - 会话 secret（webshell 口令、penelope token）只进加密库，工具入参与
// 出参一律只含元数据，绝不回显 secret；
// - webshell 驱动拒绝明文（见 session.NewHTTPShell)，失败降级必须明说，
// 绝不静默走明文；
// - session_recon 只跑只读命令包，不发探测包；
// - tunnel_deploy 只标 alive 于决定性验证通过之后，失败留痕（attempt）
// 且台账行保留、可重试。
package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/recon"
	"github.com/Autumn-27/artex/session"
	"github.com/Autumn-27/artex/tunnel"
	actool "github.com/Autumn-27/norma/tool"
)

// sessionStore builds the task's session store (AES-GCM, key derived from
// jwt.key). nil when the asset store or the key is missing.
func (t *ToolSet) sessionStore() *db.SessionStore {
	if t.as == nil || len(t.credKey) == 0 {
		return nil
	}
	return db.NewSessionStore(t.as.DB(), t.credKey)
}

// penelopeCaller 返回当前 penelope MCP 调用器（reverse manager 未启动时为 nil)。
func (t *ToolSet) penelopeCaller() session.MCPCaller {
	if t.reverseMgr == nil {
		return nil
	}
	return t.reverseMgr.Caller()
}

// SetReverseManager wires the managed penelope handler (reverse sessions 的
// MCP 调用器来源）。nil = reverse 会话不可用。
func (t *ToolSet) SetReverseManager(m *session.ReverseManager) { t.reverseMgr = m }

// SetTunnelManager wires the tunnel deploy manager. nil = tunnel_deploy 不可用。
func (t *ToolSet) SetTunnelManager(m *tunnel.Manager) { t.tunnelMgr = m }

// lookupSessionDriver 按 id 取会话记录（校验归属本任务）并建驱动。
func (t *ToolSet) lookupSessionDriver(ctx context.Context, id int64) (session.Session, *db.SessionRecord, error) {
	st := t.sessionStore()
	if st == nil {
		return nil, nil, fmt.Errorf("会话子系统不可用（缺 asset store 或 jwt.key)")
	}
	rec, err := st.Get(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if rec == nil {
		return nil, nil, session.ErrSessionNotFound
	}
	if t.taskID != 0 && rec.TaskID != t.taskID {
		return nil, nil, fmt.Errorf("会话 %d 不属于本任务", id)
	}
	drv, err := session.DriverFor(rec, t.penelopeCaller())
	if err != nil {
		return nil, rec, err
	}
	return drv, rec, nil
}

// sessionMeta 是工具出参里的会话元数据（不含 secret)。
func sessionMeta(rec *db.SessionRecord) map[string]any {
	return map[string]any{
		"session_id": rec.ID, "task_id": rec.TaskID, "kind": rec.Kind,
		"host_asset_id": rec.HostAssetID, "credential_id": rec.CredentialID,
		"url": rec.URL, "lang": rec.Lang, "status": rec.Status,
		"last_beat": rec.LastBeat.Format(time.RFC3339),
		"stale":     rec.IsStale(time.Now()),
	}
}

func (t *ToolSet) registerSession() actool.CoreTool {
	return t.writeExpTool("register_session",
		"登记一个立足点会话（webshell / 反弹 shell / ssh）。kind=http_php|http_jsp|http_aspx|reverse|ssh；"+
			"http 类需 url + password + encoder(aes|xor，明文 encoder=raw 须显式 allow_plaintext=true，否则拒绝登记）；"+
			"reverse 类需 pen_session_id（penelope 会话号，见 reverse_listen 同步结果）。"+
			"登记后立即 Test：不通则记为 dead 并如实返回失败原因（会话仍登记，可修复后重新登记）。secret 只进加密库，出参不回显。",
		obj(map[string]any{
			"kind":            str("会话类型：http_php|http_jsp|http_aspx|reverse|ssh"),
			"url":             str("webshell URL（http 类必填）"),
			"password":        str("webshell 连接口令（http 类必填，aes/xor 加密必填）"),
			"encoder":         str("webshell 编码器：aes|xor|raw（缺省 aes；raw 须显式 allow_plaintext=true)"),
			"script_type":     str("脚本类型：php|jsp|aspx（缺省按 kind 推断）"),
			"allow_plaintext": map[string]any{"type": "boolean", "description": "是否允许明文通道（仅测试用，生产勿开）"},
			"pen_session_id":  idp("penelope 会话号（reverse 类必填）"),
			"host_asset_id":   idp("关联的立足点主机资产 id（可选）"),
			"credential_id":   idp("关联的凭据 id（可选）"),
			"lang":            str("目标语言/备注（可选，如 php5.6/jsp)"),
		}, "kind"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
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
			if err := json.Unmarshal(raw, &in); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			st := t.sessionStore()
			if st == nil {
				return actool.Errorf("会话子系统不可用（缺 asset store 或 jwt.key)"), nil
			}
			secret, err := buildSessionSecret(in.Kind, in.URL, in.Password, in.Encoder, in.ScriptType, in.AllowPlaintext, in.PenSessionID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			rec := &db.SessionRecord{
				TaskID: t.taskID, Kind: in.Kind, HostAssetID: in.HostAssetID,
				CredentialID: in.CredentialID, URL: in.URL, Secret: string(secret),
				Lang: in.Lang, Status: db.SessionAlive, CreatedByTask: t.taskID,
			}
			id, err := st.Create(ctx, rec)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			drv, _, derr := t.lookupSessionDriver(ctx, id)
			if derr != nil {
				_ = st.UpdateStatus(ctx, id, db.SessionDead)
				return jsonResult(map[string]any{
					"session_id": id, "status": db.SessionDead,
					"error": "会话已登记但驱动不可用：" + derr.Error(),
				})
			}
			tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := drv.Test(tctx); err != nil {
				_ = st.UpdateStatus(ctx, id, db.SessionDead)
				return jsonResult(map[string]any{
					"session_id": id, "status": db.SessionDead,
					"error": "会话已登记但连通测试失败：" + err.Error(),
				})
			}
			rec, _ = st.Get(ctx, id)
			return jsonResult(map[string]any{"session": sessionMeta(rec), "tested": true})
		})
}

// buildSessionSecret 按 kind 组装会话 secret JSON（明文口令只在此处出现，
// 调用方 Create 即加密落库；出参绝不回显）。
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

func (t *ToolSet) sessionExec() actool.CoreTool {
	return t.writeExpTool("session_exec",
		"经立足点会话执行一条命令（stdout/stderr 合并返回）。超时默认 60 秒（上限 300 秒）。"+
			"命令在目标侧执行——只跑授权范围内的只读/诊断命令，禁止主动扫描与破坏性操作。",
		obj(map[string]any{
			"session_id":  idp("register_session 返回的会话 id"),
			"cmd":         str("要执行的命令（单条）"),
			"timeout_sec": intp("超时秒数（默认 60，上限 300)"),
		}, "session_id", "cmd"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
				SessionID  int64  `json:"session_id"`
				Cmd        string `json:"cmd"`
				TimeoutSec int    `json:"timeout_sec"`
			}
			if err := json.Unmarshal(raw, &in); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			drv, _, err := t.lookupSessionDriver(ctx, in.SessionID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			to := time.Duration(in.TimeoutSec) * time.Second
			if to <= 0 {
				to = 60 * time.Second
			}
			if to > 300*time.Second {
				to = 300 * time.Second
			}
			stdout, stderr, err := drv.Exec(ctx, in.Cmd, to)
			if st := t.sessionStore(); st != nil {
				st.Touch(ctx, in.SessionID)
			}
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"session_id": in.SessionID, "stdout": stdout, "stderr": stderr,
			})
		})
}

func (t *ToolSet) sessionRead() actool.CoreTool {
	return t.writeExpTool("session_read",
		"经立足点会话读目标侧一个文件（内容 base64 返回）。",
		obj(map[string]any{
			"session_id": idp("register_session 返回的会话 id"),
			"path":       str("目标侧文件路径"),
		}, "session_id", "path"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
				SessionID int64  `json:"session_id"`
				Path      string `json:"path"`
			}
			if err := json.Unmarshal(raw, &in); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			drv, _, err := t.lookupSessionDriver(ctx, in.SessionID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			data, err := drv.ReadFile(ctx, in.Path)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if st := t.sessionStore(); st != nil {
				st.Touch(ctx, in.SessionID)
			}
			return jsonResult(map[string]any{
				"session_id": in.SessionID, "path": in.Path,
				"size": len(data), "data_base64": base64.StdEncoding.EncodeToString(data),
			})
		})
}

func (t *ToolSet) sessionWrite() actool.CoreTool {
	return t.writeExpTool("session_write",
		"经立足点会话写目标侧一个文件（data_base64 解码后写入；大文件驱动内部分块）。"+
			"只写授权范围内的文件，禁止覆盖系统关键文件。",
		obj(map[string]any{
			"session_id":  idp("register_session 返回的会话 id"),
			"path":        str("目标侧文件路径"),
			"data_base64": str("文件内容（base64)"),
		}, "session_id", "path", "data_base64"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
				SessionID  int64  `json:"session_id"`
				Path       string `json:"path"`
				DataBase64 string `json:"data_base64"`
			}
			if err := json.Unmarshal(raw, &in); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			data, err := base64.StdEncoding.DecodeString(in.DataBase64)
			if err != nil {
				return actool.Errorf("data_base64 解码失败: " + err.Error()), nil
			}
			drv, _, err := t.lookupSessionDriver(ctx, in.SessionID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if err := drv.WriteFile(ctx, in.Path, data); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if st := t.sessionStore(); st != nil {
				st.Touch(ctx, in.SessionID)
			}
			return jsonResult(map[string]any{
				"session_id": in.SessionID, "path": in.Path, "size": len(data), "written": true,
			})
		})
}

func (t *ToolSet) reverseListen() actool.CoreTool {
	return t.writeExpTool("reverse_listen",
		"启动/复用 penelope 反弹 shell 接管端（MCP），并把已连上的反弹会话同步登记为 reverse 类立足点会话。"+
			"penelope 未配置时如实报错，不伪造就绪。已登记过的 pen 会话不再重复登记。",
		obj(map[string]any{
			"port": intp("接管端监听端口（默认 4444，须在平台侧可绑）"),
		}),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
				Port int `json:"port"`
			}
			if err := json.Unmarshal(raw, &in); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if t.reverseMgr == nil {
				return actool.Errorf("penelope 未配置（未设 ARTEX_PENELOPE_BIN 或 ARTEX_PENELOPE_MCP_URL)，无法接管反弹 shell"), nil
			}
			portOut := in.Port
			if portOut <= 0 {
				portOut = 4444
			}
			if err := t.reverseMgr.Start(ctx, in.Port); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			caller := t.reverseMgr.Caller()
			if caller == nil {
				return actool.Errorf("penelope 接管端未就绪（MCP 握手失败）"), nil
			}
			st := t.sessionStore()
			if st == nil {
				return actool.Errorf("会话子系统不可用（缺 asset store 或 jwt.key)"), nil
			}
			penSessions, err := session.ListPenelopeSessions(ctx, caller)
			if err != nil {
				return actool.Errorf("列 penelope 会话失败: " + err.Error()), nil
			}
			existing, _ := st.ListByTask(ctx, t.taskID, "")
			known := map[int64]bool{}
			for _, r := range existing {
				if r.Kind != db.SessionReverse {
					continue
				}
				var sec struct {
					PenSessionID int64 `json:"pen_session_id"`
				}
				if json.Unmarshal([]byte(r.Secret), &sec) == nil && sec.PenSessionID > 0 {
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
					"mcp_url":        t.reverseMgr.MCPURL(),
					"token":          t.reverseMgr.Token(),
				})
				rec := &db.SessionRecord{
					TaskID: t.taskID, Kind: db.SessionReverse, Secret: string(sec),
					Status: db.SessionAlive, CreatedByTask: t.taskID,
					Lang: ps.OS,
				}
				id, err := st.Create(ctx, rec)
				if err != nil {
					continue
				}
				synced = append(synced, id)
			}
			return jsonResult(map[string]any{
				"listening": true, "port": portOut,
				"penelope_sessions": len(penSessions), "synced_new": synced,
			})
		})
}

// reconCommands 被动侦察命令包（全部只读；每条单独执行单独取输出，避开
// session_exec 的输出截断；目标无 ip/ss 时 shell 级 || 回退）。
var reconCommands = []struct {
	key string
	cmd string
}{
	{"nics", "ip -o -4 addr show 2>/dev/null || ifconfig -a 2>/dev/null"},
	{"routes", "ip route 2>/dev/null || route -n 2>/dev/null"},
	{"neighbors", "ip neigh 2>/dev/null || arp -a 2>/dev/null"},
	{"hosts", "cat /etc/hosts 2>/dev/null"},
	{"conns", "(ss -ant 2>/dev/null; ss -anu 2>/dev/null) || netstat -an 2>/dev/null"},
}

func (t *ToolSet) sessionRecon() actool.CoreTool {
	return t.writeExpTool("session_recon",
		"经立足点会话在目标侧执行被动侦察命令包（ip addr / ip route / arp -a / /etc/hosts / netstat，"+
			"目标无 ip 命令自动回退 ifconfig/route -n)，不发任何探测包。"+
			"输出结构化报告（网卡/路由/邻居/hosts/监听端口/已建立对端）+ 高价值推断（非默认静态路由指向的网段、"+
			"已证明可通的对端主机、多网卡跳板）；发现的存活 IP 自动登记为 ip 资产、监听端口登记为 service 资产，"+
			"报告存 session_recon_reports，推断 record_fact 进探索图；scope 外的新网段按 /24 登记 pending_scope 等人工审批。",
		obj(map[string]any{
			"session_id": idp("register_session 返回的会话 id"),
		}, "session_id"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
				SessionID int64 `json:"session_id"`
			}
			if err := json.Unmarshal(raw, &in); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			drv, _, err := t.lookupSessionDriver(ctx, in.SessionID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			// 逐条执行：每条单独取输出，失败不中断整体——被动侦察「拿到什么算什么」。
			outputs := map[string]string{}
			cmdErrs := map[string]string{}
			for _, c := range reconCommands {
				stdout, _, err := drv.Exec(ctx, c.cmd, 15*time.Second)
				if err != nil {
					cmdErrs[c.key] = err.Error()
					continue
				}
				outputs[c.key] = stdout
			}
			if st := t.sessionStore(); st != nil {
				st.Touch(ctx, in.SessionID)
			}
			report := &recon.ReconReport{
				NICs:         recon.ParseNICsAuto(outputs["nics"]),
				Routes:       recon.ParseRoutesAuto(outputs["routes"]),
				Neighbors:    recon.ParseNeighbors(outputs["neighbors"]),
				HostsEntries: recon.ParseHosts(outputs["hosts"]),
			}
			report.Listening, report.Peers = recon.ParseConnTable(outputs["conns"])
			inferences := recon.Infer(report)

			assetIDs, assetSummary, assetErrs := t.reconInsertAssets(ctx, report)
			if st := t.sessionStore(); st != nil {
				if raw, err := json.Marshal(report); err == nil {
					_, _ = st.SaveReconReport(ctx, t.taskID, in.SessionID, raw)
				}
			}
			factID := int64(0)
			if t.ts != nil {
				ri := RunInfoFrom(ctx)
				lines := []string{}
				for _, i := range inferences {
					line := "· " + i.Summary
					if i.Detail != "" {
						line += " — " + i.Detail
					}
					lines = append(lines, line)
				}
				detail := reconSummary(report, inferences)
				if len(lines) > 0 {
					detail += "\n高价值推断:\n" + strings.Join(lines, "\n")
				}
				if id, err := t.recordOneFact(factItem{
					Summary:    fmt.Sprintf("session %d 内网被动侦察:%s", in.SessionID, reconSummary(report, inferences)),
					Detail:     detail,
					Evidence:   "session_recon 被动命令包（ip addr/ip route/arp -a/hosts/netstat，只读）",
					Confidence: "observed",
					IntentID:   json.RawMessage(fmt.Sprintf("%d", ri.IntentID)),
					AssetIDs:   toRawIDs(assetIDs),
				}, ri.IntentID); err == nil {
					factID = id
				}
			}
			out := map[string]any{
				"report":     report,
				"inferences": inferences,
				"summary":    reconSummary(report, inferences),
			}
			if assetSummary != "" {
				out["assets"] = assetSummary
			}
			if factID > 0 {
				out["fact_id"] = factID
			}
			if len(cmdErrs) > 0 {
				out["command_errors"] = cmdErrs
			}
			if len(assetErrs) > 0 {
				out["asset_errors"] = assetErrs
			}
			return jsonResult(out)
		})
}

// reconSummary 给模型的一句话摘要。
func reconSummary(r *recon.ReconReport, inf []recon.Inference) string {
	static := 0
	for _, rt := range r.Routes {
		if rt.IsStatic {
			static++
		}
	}
	return fmt.Sprintf("网卡 %d / 路由 %d（静态 %d)/ 邻居 %d / hosts %d / 监听 %d / 已建立对端 %d；高价值推断 %d 条",
		len(r.NICs), len(r.Routes), static, len(r.Neighbors), len(r.HostsEntries),
		len(r.Listening), len(r.Peers), len(inf))
}

// reconInsertAssets 把侦察发现落资产库（best-effort)：邻居/对端/hosts/本机 NIC 的
// 新 IP → ip 资产；监听端口 → 本机主 IP 上的 service 资产；scope 外的新网段
// 按 /24 登记 pending_scope 等人工审批。
func (t *ToolSet) reconInsertAssets(ctx context.Context, r *recon.ReconReport) ([]int64, string, []string) {
	if t.as == nil || t.taskID <= 0 {
		return nil, "", nil
	}
	ids := []int64{}
	errs := []string{}
	seenIP := map[string]bool{}
	ipCount := 0
	addIP := func(ip string) {
		if ip == "" || seenIP[ip] {
			return
		}
		seenIP[ip] = true
		id, err := t.as.UpsertIP(db.UpsertIPReq{IP: ip, TaskID: t.taskID})
		if err != nil {
			errs = append(errs, fmt.Sprintf("ip %s: %v", ip, err))
			return
		}
		ids = append(ids, id)
		ipCount++
	}
	hostIP := ""
	for _, n := range r.NICs {
		addr := n.IP
		if strings.HasPrefix(addr, "127.") || strings.HasPrefix(addr, "169.254.") {
			continue
		}
		if hostIP == "" {
			hostIP = addr
		}
		addIP(addr)
	}
	for _, nb := range r.Neighbors {
		addIP(nb.IP)
	}
	for _, p := range r.Peers {
		addIP(p.IP)
	}
	for _, h := range r.HostsEntries {
		if strings.HasPrefix(h.IP, "127.") {
			continue
		}
		addIP(h.IP)
	}
	svcCount := 0
	if hostIP != "" {
		for _, l := range r.Listening {
			name := recon.ServiceOf(l.Port)
			if name == "" {
				name = fmt.Sprintf("unknown-%d", l.Port)
			}
			id, err := t.as.UpsertOtherService(db.UpsertOtherServiceReq{
				IP: hostIP, Port: l.Port, ServiceName: name, TaskID: t.taskID,
			})
			if err != nil {
				errs = append(errs, fmt.Sprintf("service %s:%d: %v", hostIP, l.Port, err))
				continue
			}
			ids = append(ids, id)
			svcCount++
		}
	}
	// scope 外的新网段按 /24 登记 pending_scope（本机 NIC 所在网段除外）。
	ownSegs := map[string]bool{}
	for _, n := range r.NICs {
		if seg := recon.SegmentOf(n.IP, 24); seg != "" {
			ownSegs[seg] = true
		}
	}
	seenSeg := map[string]bool{}
	for ip := range seenIP {
		seg := recon.SegmentOf(ip, 24)
		if seg == "" || ownSegs[seg] || seenSeg[seg] {
			continue
		}
		seenSeg[seg] = true
		if t.as.DB().TaskScopeHasHost(t.taskID, ip) {
			continue
		}
		_, _ = t.as.UpsertPendingScope(t.taskID, "cidr", seg)
	}
	summary := fmt.Sprintf("登记 ip 资产 %d 个、service 资产 %d 个", ipCount, svcCount)
	if len(ids) > 20 {
		ids = ids[:20] // 锚定列表控制规模
	}
	return ids, summary, errs
}

// toRawIDs 把资产 id 列表转成 record_fact 要的 RawMessage 列表。
func toRawIDs(ids []int64) []json.RawMessage {
	out := []json.RawMessage{}
	for _, id := range ids {
		out = append(out, json.RawMessage(fmt.Sprintf("%d", id)))
	}
	return out
}

func (t *ToolSet) tunnelDeploy() actool.CoreTool {
	return t.writeExpTool("tunnel_deploy",
		"把已建计划的隧道投递到立足点远端并拉起（chisel 反向隧道 / suo5 HTTP 隧道，复用 tunnel_plan 的计划与选型）。"+
			"只对 state=deploying 或 error 的台账行部署（error 行即重试）；只有隧道内决定性验证通过才标 alive，"+
			"失败时台账标 error 并记一条投递尝试（tunnel_deploy_attempts），进程与远端文件按层回滚，不删台账行。",
		obj(map[string]any{
			"tunnel_id":  idp("tunnel_plan 返回的隧道 id"),
			"session_id": idp("经哪个立足点部署（缺省用计划的 via_session_id)"),
		}, "tunnel_id"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
				TunnelID  int64 `json:"tunnel_id"`
				SessionID int64 `json:"session_id"`
			}
			if err := json.Unmarshal(raw, &in); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if t.tunnelMgr == nil {
				return actool.Errorf("隧道部署不可用（tunnel manager 未装配）"), nil
			}
			ts := t.tunnelStore()
			if ts == nil {
				return actool.Errorf("隧道台账不可用（缺 asset store)"), nil
			}
			rec, err := ts.Get(ctx, in.TunnelID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if rec == nil {
				return actool.Errorf(fmt.Sprintf("隧道 %d 不存在", in.TunnelID)), nil
			}
			if t.taskID != 0 && rec.TaskID != t.taskID {
				return actool.Errorf(fmt.Sprintf("隧道 %d 不属于本任务", in.TunnelID)), nil
			}
			if rec.State != db.TunnelDeploying && rec.State != db.TunnelError {
				return actool.Errorf(fmt.Sprintf("隧道 %d 当前状态 %s，不可部署（仅 deploying/error 可部署/重试）", in.TunnelID, rec.State)), nil
			}
			sessID := in.SessionID
			if sessID <= 0 {
				sessID = rec.ViaSessionID
			}
			if sessID <= 0 {
				return actool.Errorf(fmt.Sprintf("隧道 %d 未指定经哪个立足点部署（计划缺 via_session_id)", in.TunnelID)), nil
			}
			drv, _, err := t.lookupSessionDriver(ctx, sessID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if err := t.tunnelMgr.DeployExisting(ctx, rec, drv); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if st := t.sessionStore(); st != nil {
				st.Touch(ctx, sessID)
			}
			rec, _ = ts.Get(ctx, in.TunnelID)
			return jsonResult(map[string]any{
				"tunnel_id": rec.ID, "state": rec.State,
				"adapter": rec.Adapter, "kind": rec.Kind,
				"entry": t.tunnelMgr.EntryAddr(mustPlan(rec)),
			})
		})
}

// mustPlan 从台账行解析部署计划（解析失败返回空计划，入口地址为空串）。
func mustPlan(rec *db.TunnelRecord) *tunnel.Plan {
	var p tunnel.Plan
	if err := json.Unmarshal(rec.DeployParams, &p); err != nil {
		return &tunnel.Plan{}
	}
	return &p
}
