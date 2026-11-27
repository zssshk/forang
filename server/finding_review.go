package server

// finding_review.go — 质量闭环 HTTP 层（Pojun 证据分级 + 质量闭环移植，v0.6.4）。
//
//   POST /api/exploration/findings/{id}/review      复核一条 finding
//     body: {verdict: confirmed|downgraded|rejected, note?, reviewer?}
//     confirmed → 状态 confirmed；downgraded → 严重度降一档 + 状态 confirmed；
//     rejected → 状态 false_positive。状态/严重度变更与复核记录同一事务落库。
//   GET  /api/exploration/findings/{id}/reviews      复核历史（最新在前）
//   GET  /api/exploration/findings/{id}/dedup-events 去重记录（复报被拦的历史）
//   GET  /api/exploration/findings/{id}/regression   确定性回归 spec（无则 null）

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Autumn-27/artex/db"
)

func (s *Server) submitFindingReview(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	var body struct {
		Verdict  string `json:"verdict"`
		Note     string `json:"note"`
		Reviewer string `json:"reviewer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if !db.ValidReviewVerdict(body.Verdict) {
		writeErr(w, 400, "bad verdict: want confirmed|downgraded|rejected")
		return
	}
	rev, err := pg.AddFindingReview(r.Context(), id, body.Reviewer, body.Verdict, body.Note)
	if err != nil {
		if errors.Is(err, db.ErrFindingNotFound) {
			writeErr(w, 404, "finding not found")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	f, err := pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	writeJSON(w, 200, map[string]any{
		"review":  rev,
		"finding": findingFromDB(f, s.resolveAssetIDs(f.AssetIDs)),
	})
}

func (s *Server) listFindingReviews(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	f, err := pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	items, err := pg.ListFindingReviews(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if items == nil {
		items = []*db.FindingQualityReview{}
	}
	writeJSON(w, 200, map[string]any{"reviews": items})
}

func (s *Server) listFindingDedupEvents(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	f, err := pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	items, err := pg.ListDedupEvents(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if items == nil {
		items = []*db.FindingDedupEvent{}
	}
	writeJSON(w, 200, map[string]any{"dedup_events": items})
}

func (s *Server) getFindingRegression(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	f, err := pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	spec, err := pg.GetFindingRegression(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"regression": spec})
}
