package session

import (
	"context"
	"strings"
	"testing"
	"time"
)

// fakeSession 是 Registry 单测用的最小 Session 实现。
type fakeSession struct {
	id   int64
	kind string
}

func (f *fakeSession) ID() int64                      { return f.id }
func (f *fakeSession) Kind() string                   { return f.kind }
func (f *fakeSession) Test(ctx context.Context) error { return nil }
func (f *fakeSession) Exec(ctx context.Context, cmd string, timeout time.Duration) (string, string, error) {
	return "ok", "", nil
}
func (f *fakeSession) ReadFile(ctx context.Context, path string) ([]byte, error) {
	return []byte("data"), nil
}
func (f *fakeSession) WriteFile(ctx context.Context, path string, data []byte) error { return nil }
func (f *fakeSession) Close(ctx context.Context) error                               { return nil }

func TestRegistryAddGetRemove(t *testing.T) {
	r := NewRegistry()
	a := &fakeSession{id: 1, kind: "http_php"}
	b := &fakeSession{id: 2, kind: "reverse"}
	r.Add(a)
	r.Add(b)
	if got, ok := r.Get(1); !ok || got != a {
		t.Fatalf("Get(1) = %v,%v, want a,true", got, ok)
	}
	if _, ok := r.Get(99); ok {
		t.Fatal("Get(99) 应该不存在")
	}
	if len(r.List()) != 2 {
		t.Fatalf("List 长度 = %d, want 2", len(r.List()))
	}
	// 同 id 覆盖。
	a2 := &fakeSession{id: 1, kind: "http_jsp"}
	r.Add(a2)
	if got, _ := r.Get(1); got != a2 {
		t.Fatal("同 id Add 应该覆盖")
	}
	if !r.Remove(1) {
		t.Fatal("Remove(1) 应该返回 true")
	}
	if r.Remove(1) {
		t.Fatal("重复 Remove 应该返回 false")
	}
	if len(r.List()) != 1 {
		t.Fatalf("Remove 后 List 长度 = %d, want 1", len(r.List()))
	}
}

func TestWorkerTmpPrefix(t *testing.T) {
	if got := WorkerTmpPrefix(3, 7); got != "/tmp/.artex_3_7_" {
		t.Fatalf("WorkerTmpPrefix = %q", got)
	}
	ctx := WithTmpPrefix(context.Background(), "/tmp/.artex_3_7_")
	if got := tmpPrefixFrom(ctx); got != "/tmp/.artex_3_7_" {
		t.Fatalf("注入前缀 = %q", got)
	}
	// 非法前缀（含分号/空格）回落默认。
	ctx = WithTmpPrefix(context.Background(), "/tmp/x; rm -rf /")
	if got := tmpPrefixFrom(ctx); got != defaultTmpPrefix {
		t.Fatalf("非法前缀应回落默认，实际 %q", got)
	}
	// 未注入用默认。
	if got := tmpPrefixFrom(context.Background()); got != defaultTmpPrefix {
		t.Fatalf("默认前缀 = %q", got)
	}
}

func TestNewHTTPShellEncryptionDiscipline(t *testing.T) {
	// 无加密配置：拒绝建会话（不静默走明文）。
	if _, err := NewHTTPShell(1, "http_php", HTTPShellConfig{URL: "http://10.0.0.1/shell.php"}); err == nil {
		t.Fatal("无 password/encoder 时应拒绝建会话")
	} else if !strings.Contains(err.Error(), "明文") {
		t.Fatalf("拒绝原因应点明明文，实际：%v", err)
	}
	// encoder=raw 且未显式允许：拒绝。
	if _, err := NewHTTPShell(1, "http_php", HTTPShellConfig{URL: "http://10.0.0.1/shell.php", Encoder: "raw"}); err == nil {
		t.Fatal("encoder=raw 未显式允许时应拒绝")
	}
	// encoder=aes 但无 password：拒绝。
	if _, err := NewHTTPShell(1, "http_php", HTTPShellConfig{URL: "http://10.0.0.1/shell.php", Encoder: "aes"}); err == nil {
		t.Fatal("aes 无 password 时应拒绝")
	}
	// aes + password：通过。
	if _, err := NewHTTPShell(1, "http_php", HTTPShellConfig{URL: "http://10.0.0.1/shell.php", Encoder: "aes", Password: "k3y"}); err != nil {
		t.Fatalf("aes + password 应通过：%v", err)
	}
	// 显式 allow_plaintext + raw：通过（调用方明说降级）。
	s, err := NewHTTPShell(1, "http_jsp", HTTPShellConfig{URL: "http://10.0.0.1/s.jsp", Encoder: "raw", AllowPlaintext: true})
	if err != nil {
		t.Fatalf("显式明文应通过：%v", err)
	}
	if s.Kind() != "http_jsp" || s.ID() != 1 {
		t.Fatalf("Kind/ID 错误：%s/%d", s.Kind(), s.ID())
	}
	// 空 URL：拒绝。
	if _, err := NewHTTPShell(1, "http_php", HTTPShellConfig{Encoder: "aes", Password: "k"}); err == nil {
		t.Fatal("空 URL 应拒绝")
	}
	// 未知类型：拒绝。
	if _, err := NewHTTPShell(1, "http_ssh", HTTPShellConfig{URL: "http://x/"}); err == nil {
		t.Fatal("未知类型应拒绝")
	}
}

func TestPenelopeSessionValidation(t *testing.T) {
	if _, err := NewPenelopeSession(1, 0, nil); err == nil {
		t.Fatal("caller 为空应拒绝")
	}
	if _, err := NewPenelopeSession(1, 3, nil); err == nil {
		t.Fatal("caller 为空应拒绝（即使 penID 合法）")
	}
	if _, err := NewPenelopeSession(1, 0, &fakeCaller{}); err == nil {
		t.Fatal("penID<=0 应拒绝")
	}
	p, err := NewPenelopeSession(7, 3, &fakeCaller{})
	if err != nil {
		t.Fatalf("合法构造应通过：%v", err)
	}
	if p.ID() != 7 || p.Kind() != "reverse" || p.PenID() != 3 {
		t.Fatalf("字段错误：%d/%s/%d", p.ID(), p.Kind(), p.PenID())
	}
}

// fakeCaller 是 penelope 单测用的最小 MCP 调用器。
type fakeCaller struct{}

func (f *fakeCaller) Call(ctx context.Context, tool string, args any) (string, error) {
	return `{"output":"hi"}`, nil
}
