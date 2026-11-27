package db

import (
	"testing"
	"time"
)

// sessionsTestDB 打开测试库（无 DSN 时跳过，与其它 db 单测同口径）。
func sessionsTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestSessionStoreRoundTrip(t *testing.T) {
	d := sessionsTestDB(t)
	ctx := t.Context()
	master := []byte("test-jwt-key-material-for-sessions")
	store := NewSessionStore(d, master)
	// 密钥缺失时 Create 应拒绝（不落明文）。
	bad := NewSessionStore(d, nil)
	if _, err := bad.Create(ctx, &SessionRecord{Kind: SessionHTTP, URL: "http://x/s.php", Secret: `{"password":"p"}`}); err == nil {
		t.Fatal("密钥缺失时 Create 应拒绝")
	}
	id, err := store.Create(ctx, &SessionRecord{
		TaskID: 424242, Kind: SessionHTTP, HostAssetID: 11, CredentialID: 5,
		URL: "http://10.0.0.1/shell.php", Secret: `{"password":"s3cr3t","encoder":"aes"}`, Lang: "php",
		CreatedByTask: 424242, CreatedByIntent: 7,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(ctx, id) })

	// 回归（v0.6.7 真测抓到）：真实登记从不设 CreatedByIntent（恒 0），
	// Create 不得把 0 转 NULL——两列是 NOT NULL DEFAULT 0，传 NULL 即 23502。
	zeroID, err := store.Create(ctx, &SessionRecord{
		TaskID: 424243, Kind: SessionSSH, URL: "ssh://ubuntu@10.0.0.2:22",
		Secret: `{"host":"10.0.0.2","username":"ubuntu"}`, CreatedByTask: 424243,
	})
	if err != nil {
		t.Fatalf("intent 为 0 时 Create 应成功: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(ctx, zeroID) })
	zero, err := store.Get(ctx, zeroID)
	if err != nil || zero == nil || zero.CreatedByIntent != 0 || zero.CreatedByTask != 424243 {
		t.Fatalf("intent 为 0 的记录回读不符：%v / %+v", err, zero)
	}

	got, err := store.Get(ctx, id)
	if err != nil || got == nil {
		t.Fatalf("Get: %v / %v", got, err)
	}
	if got.Secret != `{"password":"s3cr3t","encoder":"aes"}` {
		t.Fatalf("secret 解密后不符：%q", got.Secret)
	}
	if got.TaskID != 424242 || got.CredentialID != 5 || got.Status != SessionAlive {
		t.Fatalf("字段不符：%+v", got)
	}
	// 落库应为密文（gcm1: 前缀），不是明文。
	var stored string
	if err := d.QueryRowContext(ctx, `SELECT secret FROM sessions WHERE id=$1`, id).Scan(&stored); err != nil {
		t.Fatalf("读密文：%v", err)
	}
	if len(stored) < 5 || stored[:5] != "gcm1:" {
		t.Fatalf("落库 secret 应为 gcm1: 密文，实际 %q", stored)
	}

	// 心跳 + 失联判定。
	store.Touch(ctx, id)
	got, _ = store.Get(ctx, id)
	if got.IsStale(time.Now()) {
		t.Fatal("刚 Touch 的会话不应判 stale")
	}
	old := &SessionRecord{Status: SessionAlive, LastBeat: time.Now().Add(-30 * time.Minute)}
	if !old.IsStale(time.Now()) {
		t.Fatal("30 分钟无心跳应判 stale")
	}
	dead := &SessionRecord{Status: SessionDead, LastBeat: time.Now().Add(-30 * time.Minute)}
	if dead.IsStale(time.Now()) {
		t.Fatal("dead 会话不应再判 stale")
	}

	// ListByTask + 状态过滤 + 状态更新 + 资产回填。
	rows, err := store.ListByTask(ctx, 424242, "")
	if err != nil || len(rows) != 1 {
		t.Fatalf("ListByTask: %v / %d", err, len(rows))
	}
	if err := store.UpdateStatus(ctx, id, SessionDead); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	rows, _ = store.ListByTask(ctx, 424242, SessionAlive)
	if len(rows) != 0 {
		t.Fatalf("标 dead 后 alive 过滤应为空，实际 %d", len(rows))
	}
	store.SetHostAsset(ctx, id, 22)
	got, _ = store.Get(ctx, id)
	if got.HostAssetID != 22 {
		t.Fatalf("SetHostAsset 后 = %d", got.HostAssetID)
	}
	if err := store.UpdateStatus(ctx, id, "weird"); err == nil {
		t.Fatal("非法状态应拒绝")
	}
	if _, err := store.Create(ctx, &SessionRecord{Kind: "http_foo", Secret: "{}"}); err == nil {
		t.Fatal("非法 kind 应拒绝")
	}
}
