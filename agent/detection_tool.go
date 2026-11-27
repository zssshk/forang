// detection_tool.go — 检测规则包的 agent 工具（v0.6.6，只读）。
//
//   - detection_check：对一条已入库 finding 重跑原子规则（写命中），
//     或对任意给定文本跑规则；带 events 时再跑关联规则。
//   - detection_triage：取当前任务的待复核队列（已按严重度/证据等级/
//     规则命中数排好序），接 v0.6.4 的复核流程。
//
// 命中只是标注：规则检测的是 FORANG 自身的运行指纹，不是漏洞本身的
// 严重程度；缺席不等于安全（见 detections 包注释）。
package agent

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/Autumn-27/artex/detections"
	actool "github.com/Autumn-27/norma/tool"
)

func (t *ToolSet) detectionDB() interface {
	RescanFindingDetections(ctx context.Context, findingID int64) ([]detections.Hit, error)
	DetectionReviewQueue(ctx context.Context, taskID int64) ([]detections.ReviewItem, error)
} {
	if t.ts == nil {
		return nil
	}
	if db := t.ts.DB(); db != nil {
		return db
	}
	return nil
}

func (t *ToolSet) detectionCheck() actool.CoreTool {
	return readTool("detection_check",
		"Run the FORANG detection rule pack (9 Sigma rules ported from artex-global detections/) against a stored finding or against free text. A hit means the recorded evidence contains a fingerprint the FORANG tool itself emits (enrichment probe User-Agent, self-update egress, guard audit marker, destructive command, recording-proxy CA); it annotates the finding, it does not grade the vulnerability. Absence does not imply safety. Read-only; rescan writes only the hit rows.",
		obj(map[string]any{
			"finding_id": intp("stored finding id to rescan (writes hit rows for this finding)"),
			"texts":      str("free texts to match, one per line or a JSON array of strings (used when finding_id is absent)"),
			"events":     str("optional JSON array of {time, source, host, text} for correlation rules (RFC3339 time)"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				FindingID int64           `json:"finding_id"`
				Texts     json.RawMessage `json:"texts"`
				Events    json.RawMessage `json:"events"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			pack, err := detections.Default()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.FindingID > 0 {
				store := t.detectionDB()
				if store == nil {
					return actool.Errorf("检测库未启用：无数据库句柄"), nil
				}
				hits, err := store.RescanFindingDetections(ctx, a.FindingID)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{
					"finding_id": a.FindingID, "hits": hits, "hit_count": len(hits),
				})
			}
			var texts []string
			if len(a.Texts) > 0 {
				if err := json.Unmarshal(a.Texts, &texts); err != nil {
					var one string
					if err := json.Unmarshal(a.Texts, &one); err != nil {
						return actool.Errorf("texts must be a string or an array of strings"), nil
					}
					texts = []string{one}
				}
			}
			ev := detections.FindingEvidence{Evidence: strings.Join(texts, "\n")}
			hits := pack.MatchFinding(ev, nil)
			out := map[string]any{"hits": hits, "hit_count": len(hits)}
			if len(a.Events) > 0 {
				var raw []struct {
					Time   string `json:"time"`
					Source string `json:"source"`
					Host   string `json:"host"`
					Text   string `json:"text"`
				}
				if err := json.Unmarshal(a.Events, &raw); err != nil {
					return actool.Errorf("events must be a JSON array of {time, source, host, text}"), nil
				}
				var events []detections.Event
				for _, e := range raw {
					tm, err := time.Parse(time.RFC3339, e.Time)
					if err != nil {
						return actool.Errorf("event time must be RFC3339: " + e.Time), nil
					}
					events = append(events, detections.Event{Time: tm, Source: e.Source, Host: e.Host, Text: e.Text})
				}
				corr := pack.EvaluateCorrelations(events, nil)
				out["correlation_hits"] = corr
				out["correlation_hit_count"] = len(corr)
			}
			return jsonResult(out)
		})
}

func (t *ToolSet) detectionTriage() actool.CoreTool {
	return readTool("detection_triage",
		"List the pending-review finding queue for the current task, sorted by severity, then evidence level (L4 first), then detection-rule hit count, then age. Use it to pick the next finding to review in the v0.6.4 review flow. Read-only.",
		obj(map[string]any{
			"limit": intp("maximum rows, default 20, max 100"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Limit int `json:"limit"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			store := t.detectionDB()
			if store == nil {
				return actool.Errorf("检测库未启用：无数据库句柄"), nil
			}
			items, err := store.DetectionReviewQueue(ctx, t.taskID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.Limit <= 0 {
				a.Limit = 20
			}
			if a.Limit > 100 {
				a.Limit = 100
			}
			if len(items) > a.Limit {
				items = items[:a.Limit]
			}
			return jsonResult(map[string]any{"queue": items, "count": len(items)})
		})
}
