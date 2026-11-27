// detections.go — 检测规则包的 HTTP 层（v0.6.6，artex-global detections/ 移植）。
//
//   - GET  /api/detections/rules：规则清单 + 开关
//   - PATCH /api/detections/rules/{rule}：启用/禁用一条规则（rule 为 Sigma UUID）
//   - GET  /api/exploration/findings/{id}/detections：一条 finding 的命中
//   - POST /api/exploration/findings/{id}/detections/rescan：重扫一条 finding
//   - GET  /api/detections/ioc.csv?task_id=：IoC 导出（finding、规则、ATT&CK、
//     资产、证据等级）
//   - GET  /api/detections/triage?task_id=：待复核队列（已排序，接 v0.6.4 复核）
//   - GET  /api/detections/coverage?task_id=：覆盖率自检（task_id 给了才跑
//     关联评估——关联规则需要真实事件时间线）
//   - GET  /api/detections/indicators.csv、navigator_layer.json、suricata.rules：
//     内嵌的防守制品下载
package server

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/detections"
)

func (s *Server) listDetectionRules(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	pack, err := detections.Default()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	rows, err := pg.ListDetectionRules(r.Context())
	if err != nil {
		// 表未建时（首次启动前）按包默认全启用返回，不报错。
		var out []db.DetectionRule
		for _, rule := range pack.Rules {
			out = append(out, db.DetectionRule{RuleID: rule.ID, Slug: rule.Slug,
				Title: rule.Title, Level: rule.Level, Kind: rule.Kind, Enabled: true})
		}
		writeJSON(w, 200, map[string]any{"rules": out, "seeded": false})
		return
	}
	// 表里缺的行（旧种子）按包补默认启用，保证清单永远是 9 条。
	seen := map[string]bool{}
	for _, row := range rows {
		seen[row.RuleID] = true
	}
	for _, rule := range pack.Rules {
		if !seen[rule.ID] {
			rows = append(rows, db.DetectionRule{RuleID: rule.ID, Slug: rule.Slug,
				Title: rule.Title, Level: rule.Level, Kind: rule.Kind, Enabled: true})
		}
	}
	writeJSON(w, 200, map[string]any{"rules": rows, "seeded": true})
}

func (s *Server) setDetectionRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	pack, err := detections.Default()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ruleID := r.PathValue("rule")
	if ruleID == "" {
		writeErr(w, 400, "missing rule id")
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if body.Enabled == nil {
		writeErr(w, 400, "enabled is required")
		return
	}
	if err := pg.SetDetectionRuleEnabled(r.Context(), pack, ruleID, *body.Enabled); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"rule_id": ruleID, "enabled": *body.Enabled})
}

func (s *Server) getFindingDetections(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	hits, err := pg.ListFindingDetections(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"finding_id": id, "detections": hits, "count": len(hits)})
}

func (s *Server) rescanFindingDetections(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	hits, err := pg.RescanFindingDetections(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"finding_id": id, "hits": hits, "hit_count": len(hits)})
}

func (s *Server) exportDetectionIoCs(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	taskID, _ := strconv.ParseInt(r.URL.Query().Get("task_id"), 10, 64)
	rows, err := pg.ListDetectionIoCs(r.Context(), taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=detections-ioc.csv")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"finding_id", "vulnclass", "finding_name", "severity", "evidence_level",
		"rule_id", "rule_slug", "rule_title", "attack_techniques", "asset_ids", "excerpt", "matched_at"})
	for _, row := range rows {
		assets := make([]string, 0, len(row.AssetIDs))
		for _, a := range row.AssetIDs {
			assets = append(assets, strconv.FormatInt(a, 10))
		}
		_ = cw.Write([]string{
			strconv.FormatInt(row.FindingID, 10), row.VulnClass, row.Name, row.Severity,
			row.EvidenceLevel, row.RuleID, row.RuleSlug, row.RuleTitle,
			strings.Join(row.Techniques, ";"), strings.Join(assets, ";"),
			row.Excerpt, row.MatchedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	cw.Flush()
}

func (s *Server) detectionTriage(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	taskID, _ := strconv.ParseInt(r.URL.Query().Get("task_id"), 10, 64)
	items, err := pg.DetectionReviewQueue(r.Context(), taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"queue": items, "count": len(items)})
}

func (s *Server) detectionCoverage(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	pack, err := detections.Default()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	enabled, _ := pg.EnabledRuleMap(r.Context(), pack)
	classes, err := pg.DistinctVulnClasses(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	rep := pack.Coverage(enabled, classes)
	out := map[string]any{"coverage": rep}
	if taskID, _ := strconv.ParseInt(r.URL.Query().Get("task_id"), 10, 64); taskID > 0 {
		events, err := pg.DetectionEventsForTask(r.Context(), taskID)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		out["task_id"] = taskID
		out["event_count"] = len(events)
		out["correlation_hits"] = pack.EvaluateCorrelations(events, enabled)
	}
	writeJSON(w, 200, out)
}

func (s *Server) downloadDetectionArtifact(filename, contentType string, body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		_, _ = w.Write(body)
	}
}
