// ssh.go 是 SSH 立足点会话驱动（v0.6.7）：把立足点 Session 接口落到
// golang.org/x/crypto/ssh 客户端上（标准 SSH 客户端驱动，不涉及载荷生成）。
//
// 认证：密码 或 PEM 私钥（二选一，可同时给，私钥优先）；私钥可带口令
// （key_passphrase）。每次操作新建连接（拨号即用、用完即关），不留僵尸
// 连接、不做连接池。
//
// 主机密钥：host_key_check=ignore（默认，信任操作员给定的目标）或
// fingerprint（须同时给 host_key_sha256 指纹，形如 SHA256:…，不符拒绝
// 连接）。默认 ignore 的口径见工具描述与 README：只连授权范围内的自有
// 目标；要防中间人请登记时钉指纹。
//
// 命令：直接经 SSH 通道执行（目标 shell 解释，无需哨兵；通道本身带退出
// 码与完整输出）。与 webshell 驱动保持同一语义：命令非零退出只返回输出
// （不把输出当错误丢掉），只有拨号/通道等传输失败才经 err 返回。
//
// 文件读写：走 base64 命令通道（不引 pkg/sftp 新依赖），分块 48KB
// （base64 后约 64KB，须小于 Linux 单个 argv 上限 128KB）；读文件先
// wc -c 限 5MB，超大拒绝并明说。
package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHSecret 是 ssh 会话 secret 的 JSON 结构（落库时 AES-GCM 加密，
// 与 http/reverse 会话同一密钥体系，见 db/sessions.go）。
type SSHSecret struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Username      string `json:"username"`
	Password      string `json:"password,omitempty"`
	PrivateKey    string `json:"private_key,omitempty"`
	KeyPassphrase string `json:"key_passphrase,omitempty"`
	HostKeyCheck  string `json:"host_key_check,omitempty"` // ignore | fingerprint（缺省 ignore）
	HostKeySHA256 string `json:"host_key_sha256,omitempty"`
	TimeoutSec    int    `json:"timeout_sec,omitempty"`
}

// BuildSSHSecret 组装 ssh 会话 secret JSON（agent 与 server 两侧共用，
// 校验逻辑只此一份）。password 与 private_key 至少给一个。
func BuildSSHSecret(host string, port int, username, password, privateKey, keyPassphrase, hostKeyCheck, hostKeySHA256 string, timeoutSec int) (json.RawMessage, error) {
	host = strings.TrimSpace(host)
	username = strings.TrimSpace(username)
	if host == "" {
		return nil, fmt.Errorf("ssh 会话须给 host")
	}
	if username == "" {
		return nil, fmt.Errorf("ssh 会话须给 username")
	}
	if port <= 0 {
		port = 22
	}
	if port > 65535 {
		return nil, fmt.Errorf("ssh 端口 %d 非法", port)
	}
	if strings.TrimSpace(password) == "" && strings.TrimSpace(privateKey) == "" {
		return nil, fmt.Errorf("ssh 会话须给 password 或 private_key（至少一种认证）")
	}
	check := strings.ToLower(strings.TrimSpace(hostKeyCheck))
	if check == "" {
		check = "ignore"
	}
	switch check {
	case "ignore":
	case "fingerprint":
		if strings.TrimSpace(hostKeySHA256) == "" {
			return nil, fmt.Errorf("host_key_check=fingerprint 须给 host_key_sha256 指纹")
		}
		if !strings.HasPrefix(hostKeySHA256, "SHA256:") {
			return nil, fmt.Errorf("host_key_sha256 须为 SHA256:… 格式（ssh-keyscan 或 ssh FingerprintSHA256 输出）")
		}
	default:
		return nil, fmt.Errorf("未知 host_key_check %q（支持 ignore|fingerprint）", hostKeyCheck)
	}
	if timeoutSec < 0 {
		return nil, fmt.Errorf("timeout_sec 不能为负")
	}
	b, err := json.Marshal(SSHSecret{
		Host: host, Port: port, Username: username, Password: password,
		PrivateKey: privateKey, KeyPassphrase: keyPassphrase,
		HostKeyCheck: check, HostKeySHA256: hostKeySHA256, TimeoutSec: timeoutSec,
	})
	if err != nil {
		return nil, err
	}
	return b, nil
}

// SSHConfig 是 SSH 会话的连接参数（来自 sessions.secret 解密后的 JSON）。
type SSHConfig struct {
	Host          string
	Port          int
	Username      string
	Password      string
	PrivateKey    string
	KeyPassphrase string
	HostKeyCheck  string // ignore | fingerprint
	HostKeySHA256 string
	Timeout       time.Duration
}

// SSHSession 是 Session 接口的 SSH 实现。
type SSHSession struct {
	id  int64
	cfg SSHConfig
}

// NewSSHSession 构造 SSH 会话驱动。配置校验失败直接报错，不建半吊子会话。
func NewSSHSession(id int64, cfg SSHConfig) (*SSHSession, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, opError("probe", "ssh host 为空")
	}
	if strings.TrimSpace(cfg.Username) == "" {
		return nil, opError("probe", "ssh username 为空")
	}
	if cfg.Port <= 0 {
		cfg.Port = 22
	}
	if cfg.Port > 65535 {
		return nil, opError("probe", "ssh 端口 %d 非法", cfg.Port)
	}
	if strings.TrimSpace(cfg.Password) == "" && strings.TrimSpace(cfg.PrivateKey) == "" {
		return nil, opError("probe", "ssh 会话未配认证（password 与 private_key 均为空）")
	}
	check := strings.ToLower(strings.TrimSpace(cfg.HostKeyCheck))
	if check == "" {
		check = "ignore"
	}
	switch check {
	case "ignore":
	case "fingerprint":
		if strings.TrimSpace(cfg.HostKeySHA256) == "" {
			return nil, opError("probe", "host_key_check=fingerprint 须配 host_key_sha256")
		}
	default:
		return nil, opError("probe", "未知 host_key_check %q（支持 ignore|fingerprint）", cfg.HostKeyCheck)
	}
	cfg.HostKeyCheck = check
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &SSHSession{id: id, cfg: cfg}, nil
}

func (s *SSHSession) ID() int64    { return s.id }
func (s *SSHSession) Kind() string { return "ssh" }

// clientConfig 组装 ssh.ClientConfig（每次拨号现算，不缓存 signer 以外状态）。
func (s *SSHSession) clientConfig() (*ssh.ClientConfig, error) {
	auth := []ssh.AuthMethod{}
	if strings.TrimSpace(s.cfg.PrivateKey) != "" {
		var signer ssh.Signer
		var err error
		if strings.TrimSpace(s.cfg.KeyPassphrase) != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(
				[]byte(s.cfg.PrivateKey), []byte(s.cfg.KeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(s.cfg.PrivateKey))
		}
		if err != nil {
			return nil, opError("probe", "私钥解析失败: %v", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if strings.TrimSpace(s.cfg.Password) != "" {
		auth = append(auth, ssh.Password(s.cfg.Password))
	}
	var hostKeyCallback ssh.HostKeyCallback
	switch s.cfg.HostKeyCheck {
	case "fingerprint":
		want := strings.TrimSpace(s.cfg.HostKeySHA256)
		hostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if got := ssh.FingerprintSHA256(key); got != want {
				return fmt.Errorf("主机密钥指纹不符（期望 %s，实得 %s），拒绝连接", want, got)
			}
			return nil
		}
	default: // ignore：只连操作员给定的授权目标，见包注释。
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	}
	return &ssh.ClientConfig{
		User:            s.cfg.Username,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         s.cfg.Timeout,
	}, nil
}

// dial 拨一条新连接（每次操作现拨现关）。x/crypto/ssh 只有无 ctx 的 Dial，
// 用 goroutine + ctx select 实现超时中断（超时后后台 Dial 的结果经带缓冲
// channel 丢弃，不留 goroutine；极端情况下一次已建好的连接可能泄漏，
// 属可接受范围——拨号超时本身已是异常路径）。
func (s *SSHSession) dial(ctx context.Context) (*ssh.Client, error) {
	cfg, err := s.clientConfig()
	if err != nil {
		return nil, err
	}
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	type res struct {
		c   *ssh.Client
		err error
	}
	done := make(chan res, 1)
	go func() {
		c, err := ssh.Dial("tcp", addr, cfg)
		done <- res{c, err}
	}()
	select {
	case <-ctx.Done():
		return nil, opError("probe", "拨号 %s 超时/取消", addr)
	case r := <-done:
		if r.err != nil {
			return nil, opError("probe", "拨号 %s 失败: %v", addr, r.err)
		}
		return r.c, nil
	}
}

// runSession 在已拨号的 client 上跑一条命令并取合并输出；ctx 超时即关
// session 中断执行。exit 非零只返回输出（与 webshell 驱动同语义）。
func runSession(ctx context.Context, client *ssh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", opError("exec", "建 SSH 通道失败: %v", err)
	}
	defer sess.Close()
	type res struct {
		out []byte
		err error
	}
	done := make(chan res, 1)
	go func() {
		out, err := sess.CombinedOutput(cmd)
		done <- res{out, err}
	}()
	select {
	case <-ctx.Done():
		_ = sess.Close()
		<-done // 等 goroutine 收尾，避免泄漏
		return "", opError("exec", "命令超时/取消")
	case r := <-done:
		if r.err != nil {
			if _, ok := r.err.(*ssh.ExitError); ok {
				// 命令本身非零退出：输出照常返回，不当传输错误。
				return string(r.out), nil
			}
			if _, ok := r.err.(*ssh.ExitMissingError); ok {
				return string(r.out), nil
			}
			return "", opError("exec", "命令执行失败: %v", r.err)
		}
		return string(r.out), nil
	}
}

// timeoutCtx 按调用方超时与驱动默认超时取较严者。
func (s *SSHSession) timeoutCtx(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	to := s.cfg.Timeout
	if timeout > 0 && timeout < to {
		to = timeout
	}
	if dl, ok := ctx.Deadline(); ok {
		if remain := time.Until(dl); remain > 0 && remain < to {
			to = remain
		}
	}
	return context.WithTimeout(ctx, to)
}

// Test 做连通性探测（echo 哨兵往返）。
func (s *SSHSession) Test(ctx context.Context) error {
	ctx, cancel := s.timeoutCtx(ctx, 0)
	defer cancel()
	client, err := s.dial(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	marker := newMarker()
	out, err := runSession(ctx, client, "echo "+marker)
	if err != nil {
		return opError("test", "探针执行失败: %v", err)
	}
	if !strings.Contains(out, marker) {
		return opError("test", "探针回显缺失（输出 %q），拒绝把不可信通道当成功", truncate(out, 200))
	}
	return nil
}

// Exec 在目标侧执行一条命令（目标 shell 解释，多行直传，无需落盘）。
func (s *SSHSession) Exec(ctx context.Context, cmd string, timeout time.Duration) (string, string, error) {
	ctx, cancel := s.timeoutCtx(ctx, timeout)
	defer cancel()
	client, err := s.dial(ctx)
	if err != nil {
		return "", "", err
	}
	defer client.Close()
	out, err := runSession(ctx, client, cmd)
	if err != nil {
		return "", "", err
	}
	return out, "", nil
}

// shellQuote 把字符串包进单引号（内嵌单引号用 '\” 转义），可安全内联进 sh 命令。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

const (
	// sshReadMax 是 ReadFile 单次读取上限（5MB，超大明说拒绝，不静默截断）。
	sshReadMax = 5 << 20
	// sshWriteChunk 是 WriteFile 单次投递上限：48KB 数据 → base64 约 64KB。
	// 须小于 Linux 单个 argv 上限 128KB（MAX_ARG_STRLEN）：命令以
	// `sh -c "<整条命令>"` 形式到远端，273KB 的块实测直接报 Argument list
	// too long、通道 EOF；48KB 留足余量。
	sshWriteChunk = 48 << 10
)

// ReadFile 读目标侧文件（base64 通道；超 5MB 拒绝）。
func (s *SSHSession) ReadFile(ctx context.Context, path string) ([]byte, error) {
	ctx, cancel := s.timeoutCtx(ctx, 0)
	defer cancel()
	client, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	sizeOut, err := runSession(ctx, client, "wc -c < "+shellQuote(path))
	if err != nil {
		return nil, opError("read", "取文件大小失败: %v", err)
	}
	size, convErr := strconv.ParseInt(strings.TrimSpace(sizeOut), 10, 64)
	if convErr != nil {
		return nil, opError("read", "文件不存在或不可读（wc -c 未返回大小，输出 %q）", truncate(sizeOut, 200))
	}
	if size > sshReadMax {
		return nil, opError("read", "文件 %d 字节，超 ReadFile 上限 5MB，拒绝读取（改用 Exec 分段取）", size)
	}
	out, err := runSession(ctx, client, "base64 -w0 < "+shellQuote(path))
	if err != nil {
		return nil, opError("read", "读文件失败: %v", err)
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	if err != nil {
		return nil, opError("read", "base64 解码失败（目标输出非 base64，前 200 字节 %q）: %v", truncate(out, 200), err)
	}
	return data, nil
}

// WriteFile 写目标侧文件（二进制安全；大文件分块 append，首块截断）。
func (s *SSHSession) WriteFile(ctx context.Context, path string, data []byte) error {
	ctx, cancel := s.timeoutCtx(ctx, 0)
	defer cancel()
	client, err := s.dial(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	if len(data) == 0 {
		if _, err := runSession(ctx, client, ": > "+shellQuote(path)); err != nil {
			return opError("write", "清空文件失败: %v", err)
		}
		return nil
	}
	for i := 0; i < len(data); i += sshWriteChunk {
		end := i + sshWriteChunk
		if end > len(data) {
			end = len(data)
		}
		chunk := base64.StdEncoding.EncodeToString(data[i:end])
		op := ">"
		if i > 0 {
			op = ">>"
		}
		cmd := fmt.Sprintf("printf '%%s' %s | base64 -d %s %s",
			shellQuote(chunk), op, shellQuote(path))
		if _, err := runSession(ctx, client, cmd); err != nil {
			return opError("write", "写文件分块失败（块 %d）: %v", i/sshWriteChunk, err)
		}
	}
	// 校验落盘大小与源一致（写坏不静默认账）。
	sizeOut, err := runSession(ctx, client, "wc -c < "+shellQuote(path))
	if err != nil {
		return opError("write", "写后校验失败（wc -c 未返回）: %v", err)
	}
	size, convErr := strconv.ParseInt(strings.TrimSpace(sizeOut), 10, 64)
	if convErr != nil || size != int64(len(data)) {
		return opError("write", "写后校验失败：目标 %q，期望 %d 字节", truncate(sizeOut, 200), len(data))
	}
	return nil
}

// Close 释放资源（SSH 驱动每次操作现拨现关，无长连接可关）。
func (s *SSHSession) Close(ctx context.Context) error { return nil }
