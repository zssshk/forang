package detections

import (
	"sort"
	"strings"
	"time"
)

// ReviewItem 是待复核队列里的一条 finding（由 db 层拼装，见 db/detections.go）。
type ReviewItem struct {
	FindingID     int64     `json:"finding_id"`
	VulnClass     string    `json:"vulnclass"`
	Name          string    `json:"name"`
	Severity      string    `json:"severity"`
	EvidenceLevel string    `json:"evidence_level"` // L1–L4，""=未分级
	Status        string    `json:"status"`
	HitCount      int       `json:"hit_count"`  // 检测规则命中数
	RuleSlugs     []string  `json:"rule_slugs"` // 命中的规则短标识
	CreatedAt     time.Time `json:"created_at"`
}

// SeverityRank 是严重度排序键（越小越优先）。
func SeverityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// EvidenceRank 是证据等级排序键（越小越优先；未分级排最后）。
func EvidenceRank(level string) int {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "L4":
		return 0
	case "L3":
		return 1
	case "L2":
		return 2
	case "L1":
		return 3
	default:
		return 4
	}
}

// SortReviewQueue 按「严重度 → 证据等级 → 规则命中数（多者优先）→ 登记时间
// （早者优先）」排待复核队列，接 v0.6.4 的复核流程：复核员先看最严重、
// 证据最硬、且检测信号最多的 finding。
func SortReviewQueue(items []ReviewItem) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if SeverityRank(a.Severity) != SeverityRank(b.Severity) {
			return SeverityRank(a.Severity) < SeverityRank(b.Severity)
		}
		if EvidenceRank(a.EvidenceLevel) != EvidenceRank(b.EvidenceLevel) {
			return EvidenceRank(a.EvidenceLevel) < EvidenceRank(b.EvidenceLevel)
		}
		if a.HitCount != b.HitCount {
			return a.HitCount > b.HitCount
		}
		return a.CreatedAt.Before(b.CreatedAt)
	})
}

// TechniqueCoverage 是一条 ATT&CK 技术的规则覆盖情况。
type TechniqueCoverage struct {
	Technique    string   `json:"technique"`
	Tactic       string   `json:"tactic"`
	EnabledRules int      `json:"enabled_rules"`
	TotalRules   int      `json:"total_rules"`
	RuleSlugs    []string `json:"rule_slugs"`
}

// ClassCoverage 是一类 finding 漏洞类别的规则覆盖情况。
type ClassCoverage struct {
	Class     string   `json:"class"`
	Covered   bool     `json:"covered"`
	RuleSlugs []string `json:"rule_slugs"`
}

// CoverageReport 是规则覆盖率自检结果：技术维与漏洞类别维各一张表，
// 无覆盖的类别与技术单独列出（不是缺陷陈述，是诚实的能力边界）。
type CoverageReport struct {
	Techniques          []TechniqueCoverage `json:"techniques"`
	Classes             []ClassCoverage     `json:"classes"`
	UncoveredClasses    []string            `json:"uncovered_classes"`
	UncoveredTechniques []string            `json:"uncovered_techniques"`
}

// classCoveredBy 报告 vulnclass 是否被某条启用规则的 finding_classes 关键词覆盖
// （关键词是类别名的子串，不区分大小写；启发式映射，见 rules.json 注释）。
func classCoveredBy(vulnclass string, r *Rule) bool {
	lc := strings.ToLower(strings.TrimSpace(vulnclass))
	if lc == "" {
		return false
	}
	for _, kw := range r.FindingClasses {
		if strings.Contains(lc, strings.ToLower(strings.TrimSpace(kw))) {
			return true
		}
	}
	return false
}

// Coverage 自检：enabled 按 Sigma ID 查开关（nil=全启用）；
// vulnclasses 是待查的去重漏洞类别（调用方从 findings 表取 distinct 值）。
func (p *Pack) Coverage(enabled map[string]bool, vulnclasses []string) CoverageReport {
	rep := CoverageReport{}
	// 技术维：按 technique 聚合（同一技术可能被多条规则覆盖）。
	byTech := map[string]*TechniqueCoverage{}
	var techOrder []string
	for _, r := range p.Rules {
		if enabled != nil && !enabled[r.ID] {
			continue
		}
		for i, tech := range r.Techniques {
			tactic := ""
			if i < len(r.Tactics) {
				tactic = r.Tactics[i]
			} else if len(r.Tactics) > 0 {
				tactic = r.Tactics[0]
			}
			tc, ok := byTech[tech]
			if !ok {
				tc = &TechniqueCoverage{Technique: tech, Tactic: tactic}
				byTech[tech] = tc
				techOrder = append(techOrder, tech)
			}
			tc.EnabledRules++
			tc.RuleSlugs = append(tc.RuleSlugs, r.Slug)
		}
	}
	// 未启用（或根本无规则）的技术也要现身：从全量规则里补。
	for _, r := range p.Rules {
		for i, tech := range r.Techniques {
			if _, ok := byTech[tech]; ok {
				continue
			}
			tactic := ""
			if i < len(r.Tactics) {
				tactic = r.Tactics[i]
			} else if len(r.Tactics) > 0 {
				tactic = r.Tactics[0]
			}
			byTech[tech] = &TechniqueCoverage{Technique: tech, Tactic: tactic}
			techOrder = append(techOrder, tech)
		}
	}
	sort.Strings(techOrder)
	for _, tech := range techOrder {
		tc := byTech[tech]
		// TotalRules：包里覆盖该技术的规则总数（不论开关）。
		for _, r := range p.Rules {
			for _, t := range r.Techniques {
				if t == tech {
					tc.TotalRules++
					break
				}
			}
		}
		rep.Techniques = append(rep.Techniques, *tc)
		if tc.EnabledRules == 0 {
			rep.UncoveredTechniques = append(rep.UncoveredTechniques, tech)
		}
	}
	// 类别维。
	seen := map[string]bool{}
	for _, vc := range vulnclasses {
		vc = strings.TrimSpace(vc)
		if vc == "" || seen[vc] {
			continue
		}
		seen[vc] = true
		cc := ClassCoverage{Class: vc}
		for _, r := range p.Rules {
			if enabled != nil && !enabled[r.ID] {
				continue
			}
			if classCoveredBy(vc, &r) {
				cc.Covered = true
				cc.RuleSlugs = append(cc.RuleSlugs, r.Slug)
			}
		}
		rep.Classes = append(rep.Classes, cc)
		if !cc.Covered {
			rep.UncoveredClasses = append(rep.UncoveredClasses, vc)
		}
	}
	sort.Slice(rep.Classes, func(i, j int) bool { return rep.Classes[i].Class < rep.Classes[j].Class })
	return rep
}
