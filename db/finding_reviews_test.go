package db

import (
	"context"
	"testing"
)

// TestFindingReviewFlow covers the v0.6.4 quality loop end to end:
// confirmed / downgraded / rejected verdicts, the audit trail, and the
// dedup-event linkage. Requires postgres (skips when unavailable).
func TestFindingReviewFlow(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	tk, err := d.CreateTask("复核流程测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)
	nodeID, err := es.AddNode(KindFinding, map[string]any{"summary": "x", "severity": "critical"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	fid, err := d.AddFinding(tk.ID, nodeID, "SQLi", "SQL 注入", "critical", "summary", "poc", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}

	// 1. downgraded：critical → high，状态 confirmed，留痕。
	rev, err := d.AddFindingReview(ctx, fid, "operator", "downgraded", "证据只有响应差异，未达 L3")
	if err != nil {
		t.Fatal(err)
	}
	if rev.PrevSeverity != "critical" || rev.NewSeverity != "high" || rev.NewStatus != "confirmed" {
		t.Fatalf("downgrade = %+v", rev)
	}
	f, _ := d.GetFinding(fid)
	if f.Severity != "high" || f.Status != "confirmed" {
		t.Fatalf("after downgrade: severity=%s status=%s", f.Severity, f.Status)
	}

	// 2. rejected：状态 false_positive。
	rev, err = d.AddFindingReview(ctx, fid, "operator", "rejected", "复现失败，属误报")
	if err != nil {
		t.Fatal(err)
	}
	if rev.NewStatus != "false_positive" {
		t.Fatalf("reject new_status=%s", rev.NewStatus)
	}

	// 3. 历史可查：两条记录，最新在前。
	hist, err := d.ListFindingReviews(fid)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 || hist[0].Verdict != "rejected" || hist[1].Verdict != "downgraded" {
		t.Fatalf("history len=%d", len(hist))
	}

	// 4. 无效结论拒绝；不存在的 finding 拒绝。
	if _, err := d.AddFindingReview(ctx, fid, "", "maybe", ""); err == nil {
		t.Error("invalid verdict must fail")
	}
	if _, err := d.AddFindingReview(ctx, fid+999999, "", "confirmed", ""); err == nil {
		t.Error("missing finding must fail")
	}

	// 5. 去重事件：写一条、按 finding 可查。
	if err := d.RecordDedupEvent(fid, "fp:abc123", tk.ID, "SQLi", "SQL 注入"); err != nil {
		t.Fatal(err)
	}
	evs, err := d.ListDedupEvents(fid)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Fingerprint != "fp:abc123" {
		t.Fatalf("dedup events len=%d", len(evs))
	}
}

// TestFindingGradeWrite covers grading at the RecordFindingTx write path:
// a high-severity finding with only L1 evidence is excluded from the formal
// report; a proof-bound L3 finding is not.
func TestFindingGradeWrite(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	tk, err := d.CreateTask("证据分级写入测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)

	low, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, VulnClass: "InfoLeak", Name: "版本泄露", Severity: "high",
		Summary: "版本泄露", Evidence: "服务器返回版本号 Apache 2.4.49", Worker: "worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	if low.EvidenceLevel != "L1" || !low.ReportExcluded {
		t.Fatalf("low-evidence high finding: %+v", low)
	}
	f, _ := d.GetFinding(low.FindingID)
	if f.EvidenceLevel != "L1" || f.Confidence != "low" || !f.ReportExcluded {
		t.Fatalf("stored grade: %+v", f)
	}

	high, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: tk.ID, VulnClass: "CMDi", Name: "命令注入", Severity: "high",
		Summary: "命令注入", Evidence: "命令执行成功，输出 uid=0(root)", Worker: "worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	if high.EvidenceLevel != "L3" || high.ReportExcluded {
		t.Fatalf("L3 high finding: %+v", high)
	}
}
