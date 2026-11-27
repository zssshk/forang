package db

import (
	"context"
	"testing"

	"github.com/Autumn-27/artex/detections"
)

// TestDetectionRulesSeedAndToggle：规则种子 9 条、开关切换、开关表生效。
// Requires postgres (skips when unavailable).
func TestDetectionRulesSeedAndToggle(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()
	pack, err := detections.Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureDetectionRules(ctx, pack); err != nil {
		t.Fatal(err)
	}
	rows, err := d.ListDetectionRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 9 {
		t.Fatalf("rules = %d, want 9", len(rows))
	}
	destructive := "f510564f-2958-4dc8-a188-3300a2f6f5a7"
	if err := d.SetDetectionRuleEnabled(ctx, pack, destructive, false); err != nil {
		t.Fatal(err)
	}
	m, err := d.EnabledRuleMap(ctx, pack)
	if err != nil {
		t.Fatal(err)
	}
	if m[destructive] {
		t.Fatalf("destructive rule should be disabled")
	}
	// 恢复启用，不影响其它测试。
	if err := d.SetDetectionRuleEnabled(ctx, pack, destructive, true); err != nil {
		t.Fatal(err)
	}
	if m, _ := d.EnabledRuleMap(ctx, pack); !m[destructive] {
		t.Fatalf("destructive rule should be enabled again")
	}
}

func detectionsTestTask(t *testing.T, d *DB) (taskID, expID int64) {
	t.Helper()
	tk, err := d.CreateTask("检测规则测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.DeleteFindingsByTask(tk.ID)
		d.DeleteTask(tk.ID)
	})
	return tk.ID, tk.ExplorationID
}

// TestDetectionMatchOnRecord：登记时原子匹配进同一事务（破坏性命令命中），
// 良性 finding 无命中；AddFinding 绕过登记路径的 finding 可由重扫补命中。
func TestDetectionMatchOnRecord(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()
	pack, err := detections.Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureDetectionRules(ctx, pack); err != nil {
		t.Fatal(err)
	}
	taskID, expID := detectionsTestTask(t, d)
	es := d.Exploration(expID)

	// 1. 登记时命中：证据含 rm -rf。
	rec, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: taskID, ExplorationID: expID,
		VulnClass: "Remote Code Execution", Name: "命令执行", Severity: "critical",
		Summary: "可执行命令", Evidence: "验证：rm -rf /tmp/x 回显成功", Worker: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	hits, err := d.ListFindingDetections(ctx, rec.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Slug != "destructive-command-hunting" {
		t.Fatalf("hits = %+v, want 1 destructive hit", hits)
	}

	// 2. 良性 finding：无命中。
	rec2, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: taskID, ExplorationID: expID,
		VulnClass: "Information Disclosure", Name: "版本泄露", Severity: "low",
		Summary: "返回版本头", Evidence: "Server: nginx/1.24", Worker: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	hits, err = d.ListFindingDetections(ctx, rec2.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("benign finding hits = %+v, want none", hits)
	}

	// 3. 重扫：AddFinding 绕过登记路径，证据含 guard 标记（token 从规则包
	// 取，不在测试里硬编码），重扫补命中。
	nodeID, err := es.AddNode(KindFinding, map[string]any{"summary": "x", "severity": "high"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	guard, ok := pack.BySlug("guard-audit-framing")
	if !ok || len(guard.Tokens) == 0 {
		t.Fatal("guard rule missing")
	}
	fid, err := d.AddFinding(taskID, nodeID, "Command Injection", "命令注入", "high",
		"summary", "工具调用被拦："+guard.Tokens[0]+"此调用被平台拦截。", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	rhits, err := d.RescanFindingDetections(ctx, fid)
	if err != nil {
		t.Fatal(err)
	}
	if len(rhits) != 1 || rhits[0].Slug != "guard-audit-framing" {
		t.Fatalf("rescan hits = %+v, want 1 guard hit", rhits)
	}
	stored, err := d.ListFindingDetections(ctx, fid)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 {
		t.Fatalf("stored hits = %d, want 1", len(stored))
	}
}

// TestDetectionReviewQueueAndIoC：复核队列排序 + IoC 导出行。
func TestDetectionReviewQueueAndIoC(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()
	pack, err := detections.Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureDetectionRules(ctx, pack); err != nil {
		t.Fatal(err)
	}
	taskID, expID := detectionsTestTask(t, d)
	es := d.Exploration(expID)
	rec, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: taskID, ExplorationID: expID,
		VulnClass: "SQL Injection", Name: "SQL 注入", Severity: "high",
		Summary: "注入", Evidence: "'; DROP TABLE users; --", Worker: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := d.DetectionReviewQueue(ctx, taskID)
	if err != nil {
		t.Fatal(err)
	}
	if len(queue) == 0 || queue[0].FindingID != rec.FindingID {
		t.Fatalf("queue head = %+v, want finding %d first", queue, rec.FindingID)
	}
	if queue[0].HitCount == 0 {
		t.Fatalf("queue head should have detection hits")
	}
	rows, err := d.ListDetectionIoCs(ctx, taskID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatalf("IoC rows empty")
	}
	found := false
	for _, row := range rows {
		if row.FindingID == rec.FindingID && row.RuleSlug == "destructive-command-hunting" {
			found = true
			if len(row.Techniques) == 0 || row.Techniques[0] != "T1485" {
				t.Fatalf("IoC techniques = %v, want T1485 first", row.Techniques)
			}
		}
	}
	if !found {
		t.Fatalf("IoC rows missing destructive hit: %+v", rows)
	}
	classes, err := d.DistinctVulnClasses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, c := range classes {
		if c == "SQL Injection" {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("distinct classes missing SQL Injection: %v", classes)
	}
}
