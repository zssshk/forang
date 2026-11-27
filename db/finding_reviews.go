package db

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"
)

// finding_reviews.go — 质量闭环（Pojun 证据分级 + 质量闭环移植，v0.6.4）。
//
// 三张表：
//   finding_reviews      复核记录：verdict 确认/降级/驳回，附复核人、备注与改前改后
//                        的状态/严重度；驳回或降级的 finding 留痕，不静默消失。
//   finding_dedup_events 指纹去重事件：report_finding 被 v0.6.2 确定性指纹拦下时
//                        也写一条，复报可查（不建新 finding 行）。
//   finding_regressions  确定性回归 spec（Pojun finding_regressions 轻量版）：
//                        入库时若绑了 proof 流量即生成一条 spec；只记录 spec，
//                        不自动回放、不自动向目标发请求。

// Review verdicts (finding_reviews.verdict).
const (
	ReviewConfirmed  = "confirmed"  // 确认：状态 → confirmed，严重度不变
	ReviewDowngraded = "downgraded" // 降级：严重度降一档，状态 → confirmed
	ReviewRejected   = "rejected"   // 驳回：状态 → false_positive，严重度不变
)

// ValidReviewVerdict reports whether s is a known review verdict.
func ValidReviewVerdict(s string) bool {
	switch s {
	case ReviewConfirmed, ReviewDowngraded, ReviewRejected:
		return true
	}
	return false
}

// ReviewVerdictLabel renders the verdict for UI.
func ReviewVerdictLabel(v string) string {
	switch v {
	case ReviewConfirmed:
		return "确认"
	case ReviewDowngraded:
		return "降级"
	case ReviewRejected:
		return "驳回"
	}
	return v
}

// DowngradeSeverity lowers severity one notch (critical→high→medium→low).
func DowngradeSeverity(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case SeverityCritical:
		return SeverityHigh
	case SeverityHigh:
		return SeverityMedium
	case SeverityMedium:
		return SeverityLow
	}
	return sev
}

// FindingQualityReview is one row of finding_reviews.
type FindingQualityReview struct {
	ID           int64     `json:"id,string"`
	FindingID    int64     `json:"finding_id,string"`
	Reviewer     string    `json:"reviewer"`
	Verdict      string    `json:"verdict"`
	Note         string    `json:"note"`
	PrevStatus   string    `json:"prev_status"`
	NewStatus    string    `json:"new_status"`
	PrevSeverity string    `json:"prev_severity"`
	NewSeverity  string    `json:"new_severity"`
	CreatedAt    time.Time `json:"created_at"`
}

// FindingDedupEvent is one row of finding_dedup_events.
type FindingDedupEvent struct {
	ID          int64     `json:"id,string"`
	FindingID   *int64    `json:"finding_id,string,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	TaskID      *int64    `json:"task_id,string,omitempty"`
	VulnClass   string    `json:"vulnclass"`
	Name        string    `json:"name"`
	CreatedAt   time.Time `json:"created_at"`
}

// FindingRegression is one row of finding_regressions (deterministic replay spec).
type FindingRegression struct {
	ID               int64      `json:"id,string"`
	FindingID        int64      `json:"finding_id,string"`
	BaselineTrafficID string    `json:"baseline_traffic_id,omitempty"`
	ProofTrafficID   string     `json:"proof_traffic_id,omitempty"`
	Method           string     `json:"method"`
	URL              string     `json:"url"`
	Assertion        string     `json:"assertion"` // token | diff | status
	ExpectedStatus   int        `json:"expected_status"`
	Token            string     `json:"token,omitempty"`
	LastVerdict      string     `json:"last_verdict,omitempty"`
	LastCheckedAt    *time.Time `json:"last_checked_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// AddFindingReview applies one review verdict to a finding and records it.
// The status/severity change and the review row land in one transaction, so a
// verdict never applies without its audit trail. Returns the recorded review.
func (d *DB) AddFindingReview(ctx context.Context, findingID int64, reviewer, verdict, note string) (*FindingQualityReview, error) {
	verdict = strings.ToLower(strings.TrimSpace(verdict))
	if !ValidReviewVerdict(verdict) {
		return nil, errors.New("无效的复核结论")
	}
	reviewer = strings.TrimSpace(reviewer)
	if reviewer == "" {
		reviewer = "operator"
	}
	if len(reviewer) > 64 {
		reviewer = reviewer[:64]
	}
	note = strings.TrimSpace(note)
	rev := &FindingQualityReview{FindingID: findingID, Reviewer: reviewer, Verdict: verdict, Note: note}
	err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var status, severity string
		if err := tx.QueryRow(`SELECT status, severity FROM findings WHERE id=$1 FOR UPDATE`, findingID).Scan(&status, &severity); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrFindingNotFound
			}
			return err
		}
		rev.PrevStatus, rev.PrevSeverity = status, severity
		switch verdict {
		case ReviewConfirmed:
			rev.NewStatus, rev.NewSeverity = FindingConfirmed, severity
		case ReviewDowngraded:
			rev.NewStatus, rev.NewSeverity = FindingConfirmed, DowngradeSeverity(severity)
		case ReviewRejected:
			rev.NewStatus, rev.NewSeverity = FindingFalsePositive, severity
		}
		if _, err := tx.Exec(`UPDATE findings SET status=$1, severity=$2 WHERE id=$3`,
			rev.NewStatus, rev.NewSeverity, findingID); err != nil {
			return err
		}
		if err := tx.QueryRow(`INSERT INTO finding_reviews
			(finding_id, reviewer, verdict, note, prev_status, new_status, prev_severity, new_severity)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id, created_at`,
			findingID, reviewer, verdict, note, rev.PrevStatus, rev.NewStatus, rev.PrevSeverity, rev.NewSeverity,
		).Scan(&rev.ID, &rev.CreatedAt); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rev, nil
}

// ListFindingReviews returns a finding's review history, newest first.
func (d *DB) ListFindingReviews(findingID int64) ([]*FindingQualityReview, error) {
	rows, err := d.Query(`SELECT id, finding_id, reviewer, verdict, note,
		prev_status, new_status, prev_severity, new_severity, created_at
		FROM finding_reviews WHERE finding_id=$1 ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*FindingQualityReview
	for rows.Next() {
		r := &FindingQualityReview{}
		if err := rows.Scan(&r.ID, &r.FindingID, &r.Reviewer, &r.Verdict, &r.Note,
			&r.PrevStatus, &r.NewStatus, &r.PrevSeverity, &r.NewSeverity, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecordDedupEvent logs one fingerprint-duplicate block (v0.6.2 dedup linkage).
// Best-effort by callers: a logging failure must never fail the tool call.
func (d *DB) RecordDedupEvent(findingID int64, fingerprint string, taskID int64, vulnClass, name string) error {
	var fid, tid *int64
	if findingID > 0 {
		fid = &findingID
	}
	if taskID > 0 {
		tid = &taskID
	}
	_, err := d.Exec(`INSERT INTO finding_dedup_events
		(finding_id, fingerprint, task_id, vulnclass, name) VALUES($1,$2,$3,$4,$5)`,
		fid, fingerprint, tid, vulnClass, name)
	return err
}

// ListDedupEvents returns a finding's dedup-block history, newest first.
func (d *DB) ListDedupEvents(findingID int64) ([]*FindingDedupEvent, error) {
	rows, err := d.Query(`SELECT id, finding_id, fingerprint, task_id, vulnclass, name, created_at
		FROM finding_dedup_events WHERE finding_id=$1 ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*FindingDedupEvent
	for rows.Next() {
		e := &FindingDedupEvent{}
		if err := rows.Scan(&e.ID, &e.FindingID, &e.Fingerprint, &e.TaskID, &e.VulnClass, &e.Name, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecordDedupEvent exposes dedup logging to the agent ToolSet (via the
// ExplorationStore, the only handle tools hold).
func (s *ExplorationStore) RecordDedupEvent(findingID int64, fingerprint string, taskID int64, vulnClass, name string) error {
	return s.db.RecordDedupEvent(findingID, fingerprint, taskID, vulnClass, name)
}

// GetFindingRegression returns a finding's regression spec, or nil when none.
func (d *DB) GetFindingRegression(findingID int64) (*FindingRegression, error) {
	r := &FindingRegression{}
	var checked sql.NullTime
	err := d.QueryRow(`SELECT id, finding_id, baseline_traffic_id, proof_traffic_id,
		method, url, assertion, expected_status, token, last_verdict, last_checked_at, created_at
		FROM finding_regressions WHERE finding_id=$1`, findingID).Scan(
		&r.ID, &r.FindingID, &r.BaselineTrafficID, &r.ProofTrafficID, &r.Method, &r.URL,
		&r.Assertion, &r.ExpectedStatus, &r.Token, &r.LastVerdict, &checked, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if checked.Valid {
		t := checked.Time
		r.LastCheckedAt = &t
	}
	return r, nil
}

var regressionTokenRe = regexp.MustCompile(`validate:([A-Za-z0-9_-]{8,128}):pass`)

// UpsertFindingRegressionTx creates/refreshes the deterministic regression spec
// for one finding (Pojun finding_regressions, assertion priority token > diff >
// status). Called inside the same transaction as finding/traffic insertion, so
// a committed finding always has its spec if it is replayable. No proof
// traffic → no spec (never fabricate one). Request headers/bodies are not
// stored here (they may hold cookies/credentials); replay reads them from the
// traffic store by traffic id.
func UpsertFindingRegressionTx(tx *sql.Tx, findingID int64, in RecordFindingInput, prepared []PreparedTrafficEvidence) error {
	if tx == nil || findingID <= 0 || len(prepared) == 0 {
		return nil
	}
	var baseline, proof *PreparedTrafficEvidence
	for i := range prepared {
		switch prepared[i].Ref.Role {
		case "proof", "verification":
			if proof == nil {
				proof = &prepared[i]
			}
		case "baseline":
			if baseline == nil {
				baseline = &prepared[i]
			}
		}
	}
	if proof == nil || strings.TrimSpace(proof.Snapshot.URL) == "" {
		return nil
	}
	assertion := "status"
	token := ""
	if m := regressionTokenRe.FindStringSubmatch(in.Evidence); len(m) == 2 {
		assertion, token = "token", m[1]
	} else if baseline != nil {
		assertion = "diff"
	}
	method := strings.ToUpper(strings.TrimSpace(proof.Snapshot.Method))
	if method == "" {
		method = "GET"
	}
	baselineID := ""
	if baseline != nil {
		baselineID = baseline.Ref.TrafficID
	}
	_, err := tx.Exec(`
INSERT INTO finding_regressions(
  finding_id, baseline_traffic_id, proof_traffic_id,
  method, url, assertion, expected_status, token)
VALUES($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT(finding_id) DO UPDATE SET
  baseline_traffic_id=EXCLUDED.baseline_traffic_id,
  proof_traffic_id=EXCLUDED.proof_traffic_id,
  method=EXCLUDED.method, url=EXCLUDED.url, assertion=EXCLUDED.assertion,
  expected_status=EXCLUDED.expected_status, token=EXCLUDED.token,
  created_at=now(), last_checked_at=NULL, last_verdict=''`,
		findingID, baselineID, proof.Ref.TrafficID,
		method, strings.TrimSpace(proof.Snapshot.URL), assertion, proof.Snapshot.Status, token)
	return err
}
