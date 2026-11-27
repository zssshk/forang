// detections.go — 检测规则包的数据库层（v0.6.6，artex-global detections/ 移植）。
//
// 两张表（见 db/schema.sql v0.6.6 节）：
//
//	detection_rules：规则开关（Sigma UUID 为主键；缺行 = 启用）；
//	finding_detections：finding 与规则的命中记录。
//
// 匹配本身是纯函数（detections 包，不碰库）；这里只负责开关、命中落库、
// IoC 导出、复核队列与事件取数。登记时的匹配挂在 RecordFindingTx 里，
// 用保存点隔离：匹配落库失败只记日志，绝不影响漏洞写入（与通知事件同口径）。
package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/detections"
)

// DetectionRule 是一条规则的开关行。
type DetectionRule struct {
	RuleID  string `json:"rule_id"`
	Slug    string `json:"slug"`
	Title   string `json:"title"`
	Level   string `json:"level"`
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
}

// FindingDetection 是一条 finding↔规则命中记录。
type FindingDetection struct {
	ID        int64     `json:"id,string"`
	FindingID int64     `json:"finding_id,string"`
	RuleID    string    `json:"rule_id"`
	Slug      string    `json:"slug"`
	Excerpt   string    `json:"excerpt"`
	MatchedAt time.Time `json:"matched_at"`
}

// EnsureDetectionRules 把规则包的全部规则种子进 detection_rules
// （已存在的不动，开关不被重置）。
func (d *DB) EnsureDetectionRules(ctx context.Context, p *detections.Pack) error {
	for _, r := range p.Rules {
		if _, err := d.ExecContext(ctx, `INSERT INTO detection_rules(rule_id,slug,title,level,kind,enabled)
VALUES($1,$2,$3,$4,$5,TRUE) ON CONFLICT (rule_id) DO NOTHING`,
			r.ID, r.Slug, r.Title, r.Level, r.Kind); err != nil {
			return fmt.Errorf("seed detection rule %s: %w", r.Slug, err)
		}
	}
	return nil
}

// ListDetectionRules 返回全部规则开关（按 slug 排序）。
func (d *DB) ListDetectionRules(ctx context.Context) ([]DetectionRule, error) {
	rows, err := d.QueryContext(ctx, `SELECT rule_id,slug,title,level,kind,enabled FROM detection_rules ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DetectionRule
	for rows.Next() {
		var r DetectionRule
		if err := rows.Scan(&r.RuleID, &r.Slug, &r.Title, &r.Level, &r.Kind, &r.Enabled); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetDetectionRuleEnabled 改一条规则的开关（行不存在时先按包信息建行）。
func (d *DB) SetDetectionRuleEnabled(ctx context.Context, p *detections.Pack, ruleID string, enabled bool) error {
	r, ok := p.ByID(ruleID)
	if !ok {
		return fmt.Errorf("unknown detection rule %s", ruleID)
	}
	_, err := d.ExecContext(ctx, `INSERT INTO detection_rules(rule_id,slug,title,level,kind,enabled)
VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (rule_id) DO UPDATE SET enabled=EXCLUDED.enabled, updated_at=now()`,
		r.ID, r.Slug, r.Title, r.Level, r.Kind, enabled)
	return err
}

// EnabledRuleMap 返回 Sigma ID → 是否启用的开关表：包里有、表里缺的行
// 视为启用（默认全开；种子只在启动时补一次，缺行也不阻塞匹配）。
func (d *DB) EnabledRuleMap(ctx context.Context, p *detections.Pack) (map[string]bool, error) {
	out := make(map[string]bool, len(p.Rules))
	for _, r := range p.Rules {
		out[r.ID] = true
	}
	rows, err := d.QueryContext(ctx, `SELECT rule_id,enabled FROM detection_rules`)
	if err != nil {
		return out, nil // 表未建时（首次启动前）默认全启用
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var enabled bool
		if err := rows.Scan(&id, &enabled); err != nil {
			return out, nil
		}
		out[id] = enabled
	}
	return out, rows.Err()
}

// EnabledRuleMapTx 是 EnabledRuleMap 的事务内版本（登记时用）。
func EnabledRuleMapTx(ctx context.Context, tx *sql.Tx, p *detections.Pack) (map[string]bool, error) {
	out := make(map[string]bool, len(p.Rules))
	for _, r := range p.Rules {
		out[r.ID] = true
	}
	rows, err := tx.QueryContext(ctx, `SELECT rule_id,enabled FROM detection_rules`)
	if err != nil {
		return out, nil // 表未建时默认全启用
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var enabled bool
		if err := rows.Scan(&id, &enabled); err != nil {
			return out, nil
		}
		out[id] = enabled
	}
	return out, rows.Err()
}
func RecordFindingDetectionsTx(ctx context.Context, tx *sql.Tx, findingID int64, hits []detections.Hit) bool {
	if len(hits) == 0 {
		return true
	}
	if _, err := tx.ExecContext(ctx, `SAVEPOINT detection_match`); err != nil {
		log.Printf("[detections] 建立保存点失败 finding=%d: %v", findingID, err)
		return false
	}
	for _, h := range hits {
		if _, err := tx.ExecContext(ctx, `INSERT INTO finding_detections(finding_id,rule_id,slug,excerpt)
VALUES($1,$2,$3,$4) ON CONFLICT (finding_id,rule_id) DO NOTHING`,
			findingID, h.RuleID, h.Slug, h.Excerpt); err != nil {
			log.Printf("[detections] 写入命中失败 finding=%d rule=%s（漏洞记录不受影响）: %v", findingID, h.Slug, err)
			if _, rbErr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT detection_match`); rbErr != nil {
				log.Printf("[detections] 回滚到保存点失败 finding=%d: %v", findingID, rbErr)
			}
			return false
		}
	}
	_, _ = tx.ExecContext(ctx, `RELEASE SAVEPOINT detection_match`)
	return true
}

// ListFindingDetections 返回一条 finding 的全部规则命中。
func (d *DB) ListFindingDetections(ctx context.Context, findingID int64) ([]FindingDetection, error) {
	rows, err := d.QueryContext(ctx, `SELECT id,finding_id,rule_id,slug,excerpt,matched_at
FROM finding_detections WHERE finding_id=$1 ORDER BY matched_at`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingDetection
	for rows.Next() {
		var h FindingDetection
		if err := rows.Scan(&h.ID, &h.FindingID, &h.RuleID, &h.Slug, &h.Excerpt, &h.MatchedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// RescanFindingDetections 对一条已有 finding 重跑原子规则并补写命中
// （证据/流量/包范围；命令范围无独立存储，重扫不覆盖——见包注释）。
func (d *DB) RescanFindingDetections(ctx context.Context, findingID int64) ([]detections.Hit, error) {
	p, err := detections.Default()
	if err != nil {
		return nil, err
	}
	enabled, _ := d.EnabledRuleMap(ctx, p)
	f, err := d.GetFinding(findingID)
	if err != nil {
		return nil, err
	}
	ev := detections.FindingEvidence{
		VulnClass: f.VulnClass, Name: f.Name, Summary: f.Summary,
		Evidence: f.Evidence, Packet: f.Packet,
	}
	if ft, err := d.GetFindingTraffic(ctx, findingID); err == nil {
		for _, b := range ft.Bindings {
			ev.Traffic = append(ev.Traffic, b.Snapshot.ReqHead, b.Snapshot.RespHead)
		}
	}
	hits := p.MatchFinding(ev, enabled)
	if len(hits) == 0 {
		return hits, nil
	}
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		RecordFindingDetectionsTx(ctx, tx, findingID, hits)
		return nil
	})
	return hits, err
}

// DetectionIoCRow 是一行 IoC 导出记录（finding × 规则命中）。
type DetectionIoCRow struct {
	FindingID     int64     `json:"finding_id,string"`
	VulnClass     string    `json:"vulnclass"`
	Name          string    `json:"name"`
	Severity      string    `json:"severity"`
	EvidenceLevel string    `json:"evidence_level"`
	RuleID        string    `json:"rule_id"`
	RuleSlug      string    `json:"rule_slug"`
	RuleTitle     string    `json:"rule_title"`
	Techniques    []string  `json:"techniques"`
	AssetIDs      []int64   `json:"asset_ids"`
	Excerpt       string    `json:"excerpt"`
	MatchedAt     time.Time `json:"matched_at"`
}

// ListDetectionIoCs 返回 IoC 导出行（taskID=0 时全任务；技术与标题由规则包补）。
func (d *DB) ListDetectionIoCs(ctx context.Context, taskID int64) ([]DetectionIoCRow, error) {
	p, err := detections.Default()
	if err != nil {
		return nil, err
	}
	var rows *sql.Rows
	if taskID > 0 {
		rows, err = d.QueryContext(ctx, `SELECT fd.finding_id,f.vulnclass,COALESCE(f.name,''),
f.severity,COALESCE(f.evidence_level,''),fd.rule_id,fd.slug,fd.excerpt,fd.matched_at,
COALESCE(f.asset_ids,'[]'::jsonb)
FROM finding_detections fd JOIN findings f ON f.id=fd.finding_id
WHERE f.task_id=$1 ORDER BY fd.matched_at`, taskID)
	} else {
		rows, err = d.QueryContext(ctx, `SELECT fd.finding_id,f.vulnclass,COALESCE(f.name,''),
f.severity,COALESCE(f.evidence_level,''),fd.rule_id,fd.slug,fd.excerpt,fd.matched_at,
COALESCE(f.asset_ids,'[]'::jsonb)
FROM finding_detections fd JOIN findings f ON f.id=fd.finding_id
ORDER BY fd.matched_at`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DetectionIoCRow
	for rows.Next() {
		var r DetectionIoCRow
		var rawAssets []byte
		if err := rows.Scan(&r.FindingID, &r.VulnClass, &r.Name, &r.Severity, &r.EvidenceLevel,
			&r.RuleID, &r.RuleSlug, &r.Excerpt, &r.MatchedAt, &rawAssets); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(rawAssets, &r.AssetIDs)
		if rule, ok := p.ByID(r.RuleID); ok {
			r.RuleTitle = rule.Title
			r.Techniques = append([]string(nil), rule.Techniques...)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DetectionReviewQueue 返回待复核队列（pending/in_progress），已按
// detections.SortReviewQueue 排好序（taskID=0 时全任务）。
func (d *DB) DetectionReviewQueue(ctx context.Context, taskID int64) ([]detections.ReviewItem, error) {
	var rows *sql.Rows
	var err error
	q := `SELECT f.id,f.vulnclass,COALESCE(f.name,''),f.severity,COALESCE(f.evidence_level,''),
COALESCE(f.status,'pending'),f.created_at,COUNT(fd.id),
COALESCE(array_to_string(array_agg(fd.slug) FILTER (WHERE fd.slug <> ''), ','), '')
FROM findings f LEFT JOIN finding_detections fd ON fd.finding_id=f.id
WHERE COALESCE(f.status,'pending') IN ('pending','in_progress')`
	if taskID > 0 {
		rows, err = d.QueryContext(ctx, q+` AND f.task_id=$1 GROUP BY f.id ORDER BY f.created_at`, taskID)
	} else {
		rows, err = d.QueryContext(ctx, q+` GROUP BY f.id ORDER BY f.created_at`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []detections.ReviewItem
	for rows.Next() {
		var it detections.ReviewItem
		var slugs string // pgx 经 database/sql 把数组字面量当 string 返，逗号拼（slug 不含逗号）
		if err := rows.Scan(&it.FindingID, &it.VulnClass, &it.Name, &it.Severity, &it.EvidenceLevel,
			&it.Status, &it.CreatedAt, &it.HitCount, &slugs); err != nil {
			return nil, err
		}
		if slugs != "" {
			it.RuleSlugs = strings.Split(slugs, ",")
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	detections.SortReviewQueue(items)
	return items, nil
}

// DistinctVulnClasses 返回 findings 表里的去重漏洞类别（覆盖率自检用）。
func (d *DB) DistinctVulnClasses(ctx context.Context) ([]string, error) {
	rows, err := d.QueryContext(ctx, `SELECT DISTINCT vulnclass FROM findings WHERE vulnclass <> '' ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var vc string
		if err := rows.Scan(&vc); err != nil {
			return nil, err
		}
		out = append(out, vc)
	}
	return out, rows.Err()
}

// DetectionEventsForTask 从任务内各 finding 已绑定的流量快照拼关联评估
// 事件：host 取快照 URL 的主机，时间取快照捕获时间，正文为请求/响应头。
// 无绑定流量的任务返回空事件——关联规则需要真实事件时间线，不凭空算。
func (d *DB) DetectionEventsForTask(ctx context.Context, taskID int64) ([]detections.Event, error) {
	rows, err := d.QueryContext(ctx, `SELECT to_jsonb(s)
FROM finding_traffic_bindings b
JOIN traffic_evidence_snapshots s ON s.id=b.snapshot_id
JOIN findings f ON f.id=b.finding_id
WHERE f.task_id=$1 ORDER BY s.captured_at`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []detections.Event
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var snap TrafficEvidenceSnapshot
		if err := json.Unmarshal(raw, &snap); err != nil {
			return nil, err
		}
		host := ""
		if u, err := url.Parse(snap.URL); err == nil {
			host = u.Hostname()
		}
		t := time.Unix(snap.CapturedAt, 0).UTC()
		if snap.CapturedAt == 0 {
			t = snap.CreatedAt.UTC()
		}
		text := strings.TrimSpace(snap.ReqHead + "\n" + snap.RespHead)
		if text == "" {
			continue
		}
		out = append(out, detections.Event{Time: t, Source: "forang-recorder", Host: host, Text: text})
	}
	return out, rows.Err()
}
