// ssh_test.go 是 SSH 会话驱动的单测（v0.6.7）。
//
// 纯函数部分（配置校验、secret 组装、shellQuote、分块）无外部依赖，随
// `go test ./session/` 跑。真机部分由 FORANG_SSH_TEST_ADDR 等环境变量门控：
// 未设则跳过；设了则对操作员自有机实测（默认 DSH 168.107.31.222:5522，
// 密钥走本机 ~/.ssh/id_ed25519，只读自有机，不碰第三方目标）。
package session

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestBuildSSHSecretValidation(t *testing.T) {
	// 缺 host / 缺 username / 无认证都应拒绝。
	if _, err := BuildSSHSecret("", 22, "ubuntu", "pw", "", "", "", "", 0); err == nil {
		t.Fatal("缺 host 应拒绝")
	}
	if _, err := BuildSSHSecret("127.0.0.1", 22, "", "pw", "", "", "", "", 0); err == nil {
		t.Fatal("缺 username 应拒绝")
	}
	if _, err := BuildSSHSecret("127.0.0.1", 22, "ubuntu", "", "", "", "", "", 0); err == nil {
		t.Fatal("password 与 private_key 均为空应拒绝")
	}
	if _, err := BuildSSHSecret("127.0.0.1", 70000, "ubuntu", "pw", "", "", "", "", 0); err == nil {
		t.Fatal("非法端口应拒绝")
	}
	// fingerprint 未给指纹应拒绝；指纹格式不对也拒绝。
	if _, err := BuildSSHSecret("127.0.0.1", 22, "ubuntu", "pw", "", "", "fingerprint", "", 0); err == nil {
		t.Fatal("fingerprint 未给指纹应拒绝")
	}
	if _, err := BuildSSHSecret("127.0.0.1", 22, "ubuntu", "pw", "", "", "fingerprint", "abc123", 0); err == nil {
		t.Fatal("非 SHA256:… 格式指纹应拒绝")
	}
	if _, err := BuildSSHSecret("127.0.0.1", 22, "ubuntu", "pw", "", "", "bogus", "", 0); err == nil {
		t.Fatal("未知 host_key_check 应拒绝")
	}
	// 正常：端口缺省 22，check 缺省 ignore。
	raw, err := BuildSSHSecret("127.0.0.1", 0, "ubuntu", "pw", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("正常组装不应报错: %v", err)
	}
	var sec SSHSecret
	if err := json.Unmarshal(raw, &sec); err != nil {
		t.Fatalf("secret 应为合法 JSON: %v", err)
	}
	if sec.Port != 22 || sec.HostKeyCheck != "ignore" || sec.Username != "ubuntu" {
		t.Fatalf("缺省值不对: %+v", sec)
	}
	// 私钥认证：password 可空。
	if _, err := BuildSSHSecret("127.0.0.1", 5522, "ubuntu", "", "-----BEGIN OPENSSH PRIVATE KEY-----", "", "", "", 0); err != nil {
		t.Fatalf("私钥认证不应报错: %v", err)
	}
}

func TestNewSSHSessionValidation(t *testing.T) {
	if _, err := NewSSHSession(1, SSHConfig{Host: "", Username: "u", Password: "p"}); err == nil {
		t.Fatal("缺 host 应拒绝建会话")
	}
	if _, err := NewSSHSession(1, SSHConfig{Host: "h", Username: "", Password: "p"}); err == nil {
		t.Fatal("缺 username 应拒绝建会话")
	}
	if _, err := NewSSHSession(1, SSHConfig{Host: "h", Username: "u"}); err == nil {
		t.Fatal("无认证应拒绝建会话")
	}
	s, err := NewSSHSession(7, SSHConfig{Host: "h", Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("正常配置不应报错: %v", err)
	}
	if s.ID() != 7 || s.Kind() != "ssh" {
		t.Fatalf("ID/Kind 不对: %d/%s", s.ID(), s.Kind())
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("Close 不应报错: %v", err)
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"simple":     "'simple'",
		"a b":        "'a b'",
		"it's":       "'it'\\''s'",
		"/tmp/x y/z": "'/tmp/x y/z'",
		"a$b`c\"d":   "'a$b`c\"d'",
		"":           "''",
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Fatalf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDriverForSSH(t *testing.T) {
	raw, err := BuildSSHSecret("127.0.0.1", 22, "ubuntu", "pw", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("BuildSSHSecret: %v", err)
	}
	drv, err := DriverFor(&db.SessionRecord{ID: 42, Kind: db.SessionSSH, Secret: string(raw)}, nil)
	if err != nil {
		t.Fatalf("DriverFor(ssh) 不应报错: %v", err)
	}
	if drv.Kind() != "ssh" || drv.ID() != 42 {
		t.Fatalf("驱动 Kind/ID 不对: %s/%d", drv.Kind(), drv.ID())
	}
	// secret 非 JSON 应报错（不建半吊子驱动）。
	if _, err := DriverFor(&db.SessionRecord{ID: 43, Kind: db.SessionSSH, Secret: "{bad json"}, nil); err == nil {
		t.Fatal("secret 解析失败应报错")
	}
}

// liveSSHSession 读环境变量建一个真机测试会话；未设 FORANG_SSH_TEST_ADDR 时跳过。
func liveSSHSession(t *testing.T) *SSHSession {
	t.Helper()
	addr := os.Getenv("FORANG_SSH_TEST_ADDR")
	if addr == "" {
		t.Skip("未设 FORANG_SSH_TEST_ADDR，跳过真机测试（设为 host:port 即可跑）")
	}
	user := os.Getenv("FORANG_SSH_TEST_USER")
	if user == "" {
		user = "ubuntu"
	}
	keyPath := os.Getenv("FORANG_SSH_TEST_KEY")
	if keyPath == "" {
		home, _ := os.UserHomeDir()
		keyPath = home + "/.ssh/id_ed25519"
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("读测试私钥 %s 失败: %v", keyPath, err)
	}
	host := addr
	var portNum int
	if _, err := parseHostPort(addr, &host, &portNum); err != nil {
		t.Fatalf("FORANG_SSH_TEST_ADDR 格式须为 host:port: %v", err)
	}
	port := portNum
	s, err := NewSSHSession(9001, SSHConfig{
		Host: host, Port: port, Username: user,
		PrivateKey: string(keyBytes),
		HostKeyCheck: func() string {
			if os.Getenv("FORANG_SSH_TEST_FINGERPRINT") != "" {
				return "fingerprint"
			}
			return "ignore"
		}(),
		HostKeySHA256: os.Getenv("FORANG_SSH_TEST_FINGERPRINT"),
		Timeout:       15 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSSHSession: %v", err)
	}
	return s
}

func parseHostPort(addr string, host *string, port *int) (int, error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return 0, errBadAddr
	}
	*host = addr[:i]
	var p int
	_, err := parseInt(addr[i+1:], &p)
	if err != nil {
		return 0, err
	}
	*port = p
	return 0, nil
}

var errBadAddr = &addrError{"地址须为 host:port"}

type addrError struct{ s string }

func (e *addrError) Error() string { return e.s }

func parseInt(s string, out *int) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errBadAddr
		}
		n = n*10 + int(c-'0')
	}
	*out = n
	return n, nil
}

func TestSSHLiveAgainstOwnHost(t *testing.T) {
	s := liveSSHSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 1) 连通性探测。
	if err := s.Test(ctx); err != nil {
		t.Fatalf("Test 失败: %v", err)
	}
	// 2) Exec：单行 + 多行 + 非零退出（输出照常返回，不当错误）。
	out, _, err := s.Exec(ctx, "echo hello-ssh && uname -m", 15*time.Second)
	if err != nil {
		t.Fatalf("Exec 失败: %v", err)
	}
	if !strings.Contains(out, "hello-ssh") {
		t.Fatalf("Exec 输出缺 hello-ssh: %q", out)
	}
	multi, _, err := s.Exec(ctx, "echo line1\necho line2", 15*time.Second)
	if err != nil {
		t.Fatalf("多行 Exec 失败: %v", err)
	}
	if !strings.Contains(multi, "line1") || !strings.Contains(multi, "line2") {
		t.Fatalf("多行 Exec 输出不对: %q", multi)
	}
	failOut, _, err := s.Exec(ctx, "echo before-fail; cat /nonexistent-xyz-123 2>&1; echo after-fail", 15*time.Second)
	if err != nil {
		t.Fatalf("非零退出不应报传输错误: %v", err)
	}
	if !strings.Contains(failOut, "before-fail") || !strings.Contains(failOut, "after-fail") {
		t.Fatalf("非零退出应照常返回输出: %q", failOut)
	}
	// 3) 文件读写往返：小文件 + 500KB 分块 + 空文件。
	tmp := "/tmp/.artex_ssh_test_" + newMarker()
	defer func() {
		_, _, _ = s.Exec(ctx, "rm -f "+shellQuote(tmp)+" "+shellQuote(tmp+"_big"), 15*time.Second)
	}()
	small := []byte("ssh-driver-write-read-check 12345\nsecond line\n")
	if err := s.WriteFile(ctx, tmp, small); err != nil {
		t.Fatalf("WriteFile 小文件失败: %v", err)
	}
	got, err := s.ReadFile(ctx, tmp)
	if err != nil {
		t.Fatalf("ReadFile 小文件失败: %v", err)
	}
	if !bytes.Equal(got, small) {
		t.Fatalf("小文件往返不一致: got %d bytes, want %d", len(got), len(small))
	}
	big := make([]byte, 500<<10)
	for i := range big {
		big[i] = byte((i*7 + 13) % 251)
	}
	if err := s.WriteFile(ctx, tmp+"_big", big); err != nil {
		t.Fatalf("WriteFile 500KB 分块失败: %v", err)
	}
	gotBig, err := s.ReadFile(ctx, tmp+"_big")
	if err != nil {
		t.Fatalf("ReadFile 500KB 失败: %v", err)
	}
	if !bytes.Equal(gotBig, big) {
		t.Fatalf("500KB 往返不一致: got %d bytes, want %d", len(gotBig), len(big))
	}
	if err := s.WriteFile(ctx, tmp, []byte{}); err != nil {
		t.Fatalf("WriteFile 空文件失败: %v", err)
	}
	gotEmpty, err := s.ReadFile(ctx, tmp)
	if err != nil {
		t.Fatalf("ReadFile 空文件失败: %v", err)
	}
	if len(gotEmpty) != 0 {
		t.Fatalf("空文件应读回 0 字节，实得 %d", len(gotEmpty))
	}
	// 4) 读不存在的文件应明确报错。
	if _, err := s.ReadFile(ctx, "/tmp/.artex_ssh_test_no_such_file_xyz"); err == nil {
		t.Fatal("读不存在的文件应报错")
	}
	// 5) 指纹钉死：错指纹应拒绝连接（仅当未用 fingerprint 模式时才另测，
	// 用 fingerprint 模式跑本测试时 Test 已覆盖正确指纹）。
	if os.Getenv("FORANG_SSH_TEST_FINGERPRINT") == "" {
		bad, err := NewSSHSession(9002, SSHConfig{
			Host: s.cfg.Host, Port: s.cfg.Port, Username: s.cfg.Username,
			PrivateKey: s.cfg.PrivateKey, HostKeyCheck: "fingerprint",
			HostKeySHA256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Timeout:       15 * time.Second,
		})
		if err != nil {
			t.Fatalf("NewSSHSession(错指纹）不应在构造期报错: %v", err)
		}
		if err := bad.Test(ctx); err == nil {
			t.Fatal("错指纹应拒绝连接")
		} else if !strings.Contains(err.Error(), "指纹不符") {
			t.Fatalf("错指纹应报指纹不符，实报: %v", err)
		}
	}
}
