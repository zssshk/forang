// intranet_tools.go 是 v0.6.3 artex-ymh 移植的内网作战 agent 工具：
//   - honeypot_check：对一组 banner/title/证书做 L1 静态签名评估（只读，
//     planner + worker 都可用；交互前先查，命中即按处置纪律降级）。
//   - register_credential：把侦察中拿到的凭据加密入库（worker；AES-GCM，
//     密钥由 jwt.key 派生，未配密钥时工具直接报不可用，绝不明文落库）。
//   - suggest_credentials：对一条凭据 × 候选主机打复用分（planner + worker；
//     只返回元数据与得分，secret 永不返回给 LLM）。
//   - tunnel_plan：生成一条隧道部署计划并记入台账（planner；选型走
//     tunnel.SelectAdapter，计划序列化进 tunnels.deploy_params；
//     远端投递走立足点会话子系统（v0.6.5 tunnel_deploy 工具），
//     台账 state 保持 deploying 直到投递验证通过才标 alive）。
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/honeydetect"
	"github.com/Autumn-27/artex/tunnel"
	actool "github.com/Autumn-27/norma/tool"
)

// honeypotCheck 是 L1 静态签名评估工具（只读）：给 banner/title/证书，
// 返回 score（0-1）与命中证据 + 处置档。交互可疑服务前先调它。
func (t *ToolSet) honeypotCheck() actool.CoreTool {
	return writeTool(
		"honeypot_check",
		"对一组服务 banner/页面标题/证书做蜜罐静态签名评估（只读）。在与可疑服务交互（登录/发包/投递）前先调：score≥0.6 为疑似蜜罐（medium），≥0.9 为高置信（high）。命中后按蜜罐处置纪律：单信号只降级交互（被动/只读），不投递/不爆破/不利用。",
		obj(map[string]any{
			"port":         str("服务端口（可选）"),
			"banner":       str("服务 banner（如 SSH banner；可选）"),
			"title":        str("页面标题（可选）"),
			"body":         str("页面正文片段（可选）"),
			"cert_subject": str("TLS 证书 subject（可选）"),
			"cert_issuer":  str("TLS 证书 issuer（可选）"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Port        int    `json:"port"`
				Banner      string `json:"banner"`
				Title       string `json:"title"`
				Body        string `json:"body"`
				CertSubject string `json:"cert_subject"`
				CertIssuer  string `json:"cert_issuer"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			score, evidence := honeydetect.Evaluate(honeydetect.ServiceView{
				Port: a.Port, Banner: a.Banner, Title: a.Title, Body: a.Body,
				CertSubject: a.CertSubject, CertIssuer: a.CertIssuer,
			})
			conf := "none"
			if score >= 0.9 {
				conf = "high"
			} else if score >= 0.6 {
				conf = "medium"
			}
			return jsonResult(map[string]any{
				"score": score, "confidence": conf, "evidence": evidence,
				"disposition": map[string]any{
					"high":   "高置信蜜罐：停止该方向，不发起客户端连接",
					"medium": "疑似蜜罐：只做被动/只读观察，不投递/不爆破/不利用",
					"none":   "无签名命中：仍按常规纪律，不投放高价值 exploit、控制噪声",
				}[conf],
			})
		},
	)
}

// registerCredential 把侦察中拿到的凭据加密入库。secret 只在内存里出现一次，
// 落库即 AES-GCM 密文（gcm1: 前缀）；凭据库未配密钥时直接报不可用。
func (t *ToolSet) registerCredential() actool.CoreTool {
	return writeTool(
		"register_credential",
		"把侦察中拿到的凭据登记进凭据库（AES-GCM 加密落库，密钥由 jwt.key 派生）。凭据类型：password / hash_nt / hash_lm / hash_sha1 / ticket / ssh_key / token。source 务必写清来源（如 \"sqli dump users 表\"）。secret 只传一次，不会回显。",
		obj(map[string]any{
			"username":      str("用户名"),
			"cred_type":     str("凭据类型：password / hash_nt / hash_lm / hash_sha1 / ticket / ssh_key / token"),
			"secret":        str("凭据 secret（明文口令/哈希/票据/密钥，只传一次）"),
			"domain":        str("域（如 CORP；本地账号留空）"),
			"source":        str("来源描述（如 \"sqli dump users 表\" / \"/etc/shadow\"）"),
			"host_asset_id": str("凭据来源主机资产 id（可选，0=未知）"),
		}, "username", "cred_type", "secret", "source"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			cs := t.credentialStore()
			if cs == nil {
				return actool.Errorf("凭据库未启用：凭据加密主钥未配置，拒绝明文落库"), nil
			}
			var a struct {
				Username    string `json:"username"`
				CredType    string `json:"cred_type"`
				Secret      string `json:"secret"`
				Domain      string `json:"domain"`
				Source      string `json:"source"`
				HostAssetID int64  `json:"host_asset_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if !db.ValidCredType(a.CredType) {
				return actool.Errorf("非法 cred_type " + strconv.Quote(a.CredType)), nil
			}
			id, err := cs.Create(ctx, &db.CredentialRecord{
				TaskID: t.taskID, HostAssetID: a.HostAssetID,
				Username: a.Username, CredType: a.CredType, Secret: a.Secret,
				Domain: a.Domain, Source: a.Source,
			})
			if err != nil {
				return actool.Errorf("凭据入库失败: " + err.Error()), nil
			}
			return jsonResult(map[string]any{"credential_id": id, "encrypted": true})
		},
	)
}

// suggestCredentials 对一条已入库凭据 × 候选主机资产打复用分，返回按得分降序
// 的建议（只含元数据：id/用户名/类型/域/来源/是否已验证 + 目标资产/得分/理由；
// secret 永不返回）。候选资产 id 来自 list_assets。
func (t *ToolSet) suggestCredentials() actool.CoreTool {
	return writeTool(
		"suggest_credentials",
		"对一条已入库凭据 × 候选主机资产打复用分（同网段 +40、域凭据 +35、已验证 +25、服务重叠 +20、NT hash +15），返回按得分降序的横向复用建议。只返回元数据与得分，secret 永不返回。候选资产 id 从 list_assets 里取。",
		obj(map[string]any{
			"credential_id": str("凭据库 id（register_credential 的返回值）"),
			"asset_ids":     str("候选主机资产 id 列表（JSON 数组，如 [12, 34]）"),
		}, "credential_id", "asset_ids"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			cs := t.credentialStore()
			if cs == nil {
				return actool.Errorf("凭据库未启用：凭据加密主钥未配置"), nil
			}
			var a struct {
				CredentialID int64   `json:"credential_id"`
				AssetIDs     []int64 `json:"asset_ids"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cred, err := cs.Get(ctx, a.CredentialID)
			if err != nil {
				return actool.Errorf("凭据不存在: " + err.Error()), nil
			}
			if t.as == nil {
				return actool.Errorf("资产库未启用"), nil
			}
			assets, err := t.as.GetByIDsInScope(t.taskID, a.AssetIDs)
			if err != nil {
				return actool.Errorf("候选资产查询失败: " + err.Error()), nil
			}
			var src *db.ReuseCandidate
			if cred.HostAssetID != 0 {
				if host, err := t.as.GetByIDsInScope(t.taskID, []int64{cred.HostAssetID}); err == nil && len(host) > 0 {
					src = assetToReuseCandidate(host[0])
				}
			}
			cands := make([]db.ReuseCandidate, 0, len(assets))
			for _, as := range assets {
				if c := assetToReuseCandidate(as); c != nil {
					cands = append(cands, *c)
				}
			}
			// 凭据元数据副本（去掉 secret，绝不返回给 LLM）。
			meta := *cred
			meta.Secret = ""
			sug := db.ScoreReuse(cred, src, cands)
			if len(sug) > 5 {
				sug = sug[:5]
			}
			return jsonResult(map[string]any{"credential": meta, "suggestions": sug})
		},
	)
}

// assetToReuseCandidate 把资产投影成复用打分的候选视图（仅含 IP 的主机资产）。
func assetToReuseCandidate(a *db.Asset) *db.ReuseCandidate {
	if a == nil || strings.TrimSpace(a.IP) == "" {
		return nil
	}
	services := []string{}
	if a.ServiceName != "" {
		services = append(services, a.ServiceName)
	}
	for _, p := range a.OpenPorts {
		if s, ok := p["service"].(string); ok && s != "" {
			services = append(services, s)
		}
	}
	return &db.ReuseCandidate{AssetID: a.ID, IP: a.IP, CSegment: a.CSegment, Services: services}
}

// tunnelPlan 生成一条隧道部署计划并记入台账（planner 用）。
// 选型：probe 驱动（tcp_out / webshell_url）→ tunnel.SelectAdapter；
// 端口池：ARTEX_TUNNEL_PORT_RANGE（默认 20000-21000），已占端口从活隧道台账取；
// 回连地址：ARTEX_CALLBACK_ADDR（无则报错，须在部署环境配好）。
// 远端投递走立足点会话子系统（v0.6.5 tunnel_deploy 工具），计划只生成 + 入账（state=deploying），
// Deploy 阶段诚实标记为后续项，不编一个假 alive。
func (t *ToolSet) tunnelPlan() actool.CoreTool {
	return writeTool(
		"tunnel_plan",
		"生成一条内网隧道部署计划并记入台账（选型 + 端口分配 + 计划持久化）。kind：socks（平台回环 socks5 入口）或 portfwd（单端口转发到内网目标）。选型规则：目标能 TCP 出网 → chisel；不能出网但有 webshell → suo5（仅 socks）；portfwd 强制 chisel。远端投递走立足点会话（v0.6.5 tunnel_deploy 工具），计划只生成 + 入账。",
		obj(map[string]any{
			"kind":         str("隧道类型：socks 或 portfwd"),
			"tcp_out":      str("目标能否直接 TCP 出网（true/false）"),
			"webshell_url": str("立足点 webshell URL（无则留空）"),
			"target_host":  str("portfwd 的内网目标 host（socks 不用）"),
			"target_port":  str("portfwd 的内网目标 port（socks 不用）"),
			"verify_addr":  str("决定性验证目标 host:port（通常立足点 host:port；可选）"),
		}, "kind", "tcp_out"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Kind        string `json:"kind"`
				TCPOut      bool   `json:"tcp_out"`
				WebshellURL string `json:"webshell_url"`
				TargetHost  string `json:"target_host"`
				TargetPort  int    `json:"target_port"`
				VerifyAddr  string `json:"verify_addr"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			adapter, reason, err := tunnel.SelectAdapter(a.Kind, tunnel.ProbeResult{TCPOut: a.TCPOut, WebshellURL: a.WebshellURL})
			if err != nil {
				return actool.Errorf("隧道选型失败: " + err.Error()), nil
			}
			callback := strings.TrimSpace(os.Getenv("ARTEX_CALLBACK_ADDR"))
			if callback == "" {
				return actool.Errorf("回连地址未配置：部署环境须设置 ARTEX_CALLBACK_ADDR（目标回连平台用的 host，如公网 IP 或域名）"), nil
			}
			callbackHost, _, err := net.SplitHostPort(callback)
			if err != nil {
				callbackHost = callback // 允许只给 host（默认端口走 ListenPort）
			}
			min, max, err := tunnel.ParsePortRange(os.Getenv("ARTEX_TUNNEL_PORT_RANGE"))
			if err != nil {
				return actool.Errorf("端口池非法: " + err.Error()), nil
			}
			used := map[int]bool{}
			ts := t.tunnelStore()
			if ts != nil {
				if alive, err := ts.ListActive(ctx); err == nil {
					for _, r := range alive {
						used[r.ListenPort] = true
						if r.Kind == tunnel.KindSocks {
							used[portFromDeployParams(r.DeployParams, "socks_port")] = true
						} else {
							used[portFromDeployParams(r.DeployParams, "local_port")] = true
						}
					}
				}
			}
			dataDir := filepath.Join(os.TempDir(), "artex-tunnels")
			_ = os.MkdirAll(dataDir, 0o700)
			opts := &tunnel.PlanOpts{
				TaskID: t.taskID, Adapter: adapter,
				CallbackHost: callbackHost, VerifyAddr: a.VerifyAddr,
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
			if a.Kind == tunnel.KindSocks {
				plan, err = tunnel.PlanSocks(opts)
			} else {
				opts.TargetHost, opts.TargetPort = a.TargetHost, a.TargetPort
				plan, err = tunnel.PlanPortfwd(opts)
			}
			if err != nil {
				return actool.Errorf("隧道计划生成失败: " + err.Error()), nil
			}
			raw, _ := json.Marshal(plan)
			var tunnelID int64
			if ts != nil {
				tunnelID, err = ts.Create(ctx, &db.TunnelRecord{
					TaskID: t.taskID, Kind: a.Kind, Adapter: adapter,
					ListenHost: plan.ListenHost, ListenPort: plan.ListenPort,
					TargetHost: a.TargetHost, TargetPort: a.TargetPort,
					DeployParams: raw, State: db.TunnelDeploying,
				})
				if err != nil {
					return actool.Errorf("隧道台账写入失败: " + err.Error()), nil
				}
			}
			out := map[string]any{
				"tunnel_id": tunnelID, "adapter": adapter, "selection_reason": reason,
				"listen": fmt.Sprintf("%s:%d", plan.ListenHost, plan.ListenPort),
				"state":  db.TunnelDeploying,
				"note":   "计划已生成并入账；远端投递走 tunnel_deploy 工具（需立足点会话），当前 state 保持 deploying，不谎报 alive",
			}
			if a.Kind == tunnel.KindSocks {
				out["socks_entry"] = fmt.Sprintf("socks5://127.0.0.1:%d", plan.SocksPort)
			} else {
				out["local_entry"] = fmt.Sprintf("127.0.0.1:%d -> %s:%d", plan.LocalPort, a.TargetHost, a.TargetPort)
			}
			return jsonResult(out)
		},
	)
}

// reportPendingScope 是 worker 的待授权网段登记工具：侦察中发现当前 task_scope
// 之外的网段时，先按 /24 聚合登记进 pending_scope，等人工批准后才扩范围；
// 绝不自行把新网段写进 task_scope。重复登记只累计 hits。
func (t *ToolSet) reportPendingScope() actool.CoreTool {
	return writeTool(
		"report_pending_scope",
		"登记一条 scope 外的网段进待授权清单（人工批准后才扩范围）。侦察中发现当前任务范围之外的新网段（如内网被动侦察扫到的 10.0.3.0/24）时调它：只登记、不扩范围。kind 固定 cidr，value 如 10.0.3.0/24。",
		obj(map[string]any{
			"value": str("网段，如 10.0.3.0/24"),
		}, "value"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("资产库未启用"), nil
			}
			var a struct {
				Value string `json:"value"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			created, err := t.as.UpsertPendingScope(t.taskID, "cidr", strings.TrimSpace(a.Value))
			if err != nil {
				return actool.Errorf("登记失败: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"created": created, "value": a.Value,
				"note": "已登记待授权；须人工批准后才进 task_scope，未批准前不得对该网段动手",
			})
		},
	)
}

// portFromDeployParams 从 deploy_params JSON 里取一个端口字段（台账占用统计用）。
func portFromDeployParams(raw json.RawMessage, field string) int {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return 0
	}
	if v, ok := m[field].(float64); ok {
		return int(v)
	}
	return 0
}
