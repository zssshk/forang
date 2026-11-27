// deploy_test.go 是隧道部署层的纯函数测试（v0.6.5)。
package tunnel

import (
	"strings"
	"testing"
)

func TestSuo5PayloadFile(t *testing.T) {
	for kind, want := range map[string]string{
		"http_php": "suo5.php", "php": "suo5.php",
		"http_jsp": "suo5.jsp", "http_aspx": "suo5.aspx",
	} {
		got, err := Suo5PayloadFile(kind)
		if err != nil || got != want {
			t.Fatalf("Suo5PayloadFile(%q)=%q,%v want %q", kind, got, err, want)
		}
	}
	if _, err := Suo5PayloadFile("http_ssh"); err == nil {
		t.Fatal("ssh 应无 suo5 payload")
	}
}

func TestSuo5PayloadURL(t *testing.T) {
	u, err := Suo5PayloadURL("http://10.0.0.5/web/shell.php?x=1", "ab12cd34.php")
	if err != nil || u != "http://10.0.0.5/web/ab12cd34.php" {
		t.Fatalf("Suo5PayloadURL=%q,%v", u, err)
	}
	if _, err := Suo5PayloadURL("not-a-url", "a.php"); err == nil {
		t.Fatal("非法 URL 应报错")
	}
}

func TestSuo5Args(t *testing.T) {
	args := Suo5Args("http://10.0.0.5/web/ab12cd34.php", 21001, "artex", "secret")
	if len(args) != 6 || args[0] != "-t" || args[3] != "127.0.0.1:21001" || args[4] != "--auth" || args[5] != "artex:secret" {
		t.Fatalf("Suo5Args=%v", args)
	}
}

func TestPlanSuo5(t *testing.T) {
	p, err := PlanSuo5(&Suo5PlanOpts{
		TaskID: 7, ViaSessionID: 3, ShellURL: "http://10.0.0.5/web/shell.php",
		SessionKind: "http_php", VerifyAddr: "10.0.0.5:80",
		PortMin: 20000, PortMax: 21000, UsedPorts: map[int]bool{},
		CanListen: func(int) bool { return true }, DataDir: "/tmp/x",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Adapter != AdapterSuo5 || p.Kind != KindSocks || p.ListenPort != p.SocksPort || p.SocksPort <= 0 {
		t.Fatalf("PlanSuo5 字段异常： %+v", p)
	}
	if !strings.HasSuffix(p.PayloadURL, p.PayloadName) || p.PayloadName == "" {
		t.Fatalf("payload URL/名异常： %q %q", p.PayloadURL, p.PayloadName)
	}
	if len(p.ServerArgs) == 0 || p.ServerArgs[0] != "-t" {
		t.Fatalf("ServerArgs 应为 suo5 参数： %v", p.ServerArgs)
	}
	if _, err := PlanSuo5(&Suo5PlanOpts{ShellURL: ""}); err == nil {
		t.Fatal("缺 shell_url 应报错")
	}
}

func TestParsePwd(t *testing.T) {
	dir, err := parsePwd("/var/www/html\n")
	if err != nil || dir != "/var/www/html" {
		t.Fatalf("parsePwd=%q,%v", dir, err)
	}
	if _, err := parsePwd("C:\\inetpub\\wwwroot\n"); err != nil {
		t.Fatalf("Windows 路径应接受： %v", err)
	}
	if _, err := parsePwd("/tmp/$(id)\n"); err == nil {
		t.Fatal("危险字符应拒绝")
	}
	if _, err := parsePwd("\n"); err == nil {
		t.Fatal("空回显应报错")
	}
}

func TestSocks5Builders(t *testing.T) {
	g := BuildSocks5Greeting()
	if len(g) != 3 || g[0] != 0x05 || g[2] != 0x00 {
		t.Fatalf("greeting=%v", g)
	}
	req, err := BuildSocks5Request("10.0.0.5", 80)
	if err != nil || req[3] != 0x01 || req[4] != 10 {
		t.Fatalf("request=%v,%v", req, err)
	}
	req, err = BuildSocks5Request("example.com", 443)
	if err != nil || req[3] != 0x03 || req[4] != 11 {
		t.Fatalf("domain request=%v,%v", req, err)
	}
	ok, code := ParseSocks5Reply([]byte{0x05, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0, 80})
	if !ok || code != 0 {
		t.Fatalf("reply parse ok=%v code=%d", ok, code)
	}
	if ok, _ := ParseSocks5Reply([]byte{0x05, 0x05}); ok {
		t.Fatal("rep=5 应为失败")
	}
	up, err := BuildSocks5UserPass("artex", "secret")
	if err != nil || !ParseSocks5UserPassReply([]byte{0x01, 0x00}) || len(up) == 0 {
		t.Fatalf("userpass=%v,%v", up, err)
	}
}

func TestNewManagerValidation(t *testing.T) {
	if _, err := NewManager(Options{}); err == nil {
		t.Fatal("缺 store/sessions 应报错")
	}
}

func TestDetailOf(t *testing.T) {
	if got := detailOf("  ok  "); got != "ok" {
		t.Fatalf("detailOf=%q", got)
	}
	if got := detailOf(strings.Repeat("x", 300)); len(got) > 205 {
		t.Fatalf("detailOf 未截断： len=%d", len(got))
	}
}
