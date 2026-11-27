// Package detections 是 FORANG v0.6.6 移植的 artex-global detections/ 检测包。
//
// 上游（jiwoochris/artex-global detections/）是一套防守规则：Sigma 规则、
// ATT&CK 覆盖层、IoC 清单、Suricata 规则与 host triage 脚本，检测的是
// ARTEX/FORANG 自身的运行指纹（富化探针 UA、自更新 UA、平台管控标记、
// 破坏性命令、录制代理 CA），不是通用漏洞类别。移植保持这一诚实口径：
// 命中一条规则只说明该 finding 的已记录证据里出现了本工具自身发出的
// 信号，不等于漏洞本身更严重；静态指纹可被改掉，缺席不等于安全。
//
// 规则数据内嵌在 detections/data/rules.json（go:embed），与 knowledge-pack
// 同做法；ATT&CK 编号只用 knowledge-pack（ATT&CK 706）里已有的 ID，
// 不另起一套编号（测试里断言）。规则开关（启用/禁用）存在数据库
// detection_rules 表，见 db/detections.go；包本身只做纯匹配，不碰库。
package detections

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed data/rules.json
var embeddedRules []byte

//go:embed data/indicators.csv
var embeddedIndicators []byte

//go:embed data/navigator_layer.json
var embeddedNavigatorLayer []byte

//go:embed data/suricata.rules
var embeddedSuricataRules []byte

// IndicatorsCSV 返回内嵌的 IoC 清单（7 行，与 rules.json 同源）。
func IndicatorsCSV() []byte { return embeddedIndicators }

// NavigatorLayer 返回内嵌的 ATT&CK 覆盖层（8 技术）。
func NavigatorLayer() []byte { return embeddedNavigatorLayer }

// SuricataRules 返回内嵌的 Suricata 规则（3 条）。
func SuricataRules() []byte { return embeddedSuricataRules }

// Correlation 是关联规则的聚合定义（上游 Sigma correlation 的可执行子集）。
type Correlation struct {
	Type            string   `json:"type"`             // event_count | value_count | temporal
	BaseRuleIDs     []string `json:"base_rule_ids"`    // 依赖的原子规则 Sigma ID
	GroupBy         string   `json:"group_by"`         // source | host
	Threshold       int      `json:"threshold"`        // 达标计数（temporal 为 1：每条基规则至少命中一次）
	TimespanMinutes int      `json:"timespan_minutes"` // 时间窗（分钟）
	Field           string   `json:"field,omitempty"`  // value_count：去重计数的字段（host）
}

// Rule 是一条 Sigma 规则的 FORANG 移植。
type Rule struct {
	ID                  string       `json:"id"` // Sigma UUID，全仓稳定标识
	Slug                string       `json:"slug"`
	Title               string       `json:"title"`
	Level               string       `json:"level"` // high | medium
	Kind                string       `json:"kind"`  // atomic | correlation
	Tactics             []string     `json:"tactics"`
	Techniques          []string     `json:"techniques"` // ATT&CK ID，与 knowledge-pack 同编号
	LogSource           string       `json:"logsource"`
	Description         string       `json:"description"`
	SourceFile          string       `json:"source_file"` // 锚定的 FORANG 源码位置
	SigmaFile           string       `json:"sigma_file"`  // 上游规则文件
	Tokens              []string     `json:"tokens"`
	TokensAll           bool         `json:"tokens_all,omitempty"` // 全部 token 都命中才算（CA 规则）
	CaseSensitiveTokens []string     `json:"case_sensitive_tokens,omitempty"`
	Scopes              []string     `json:"scopes"`          // evidence | traffic | packet | commands
	FindingClasses      []string     `json:"finding_classes"` // 启发式关键词映射，见包注释
	SuricataSIDs        []int        `json:"suricata_sids,omitempty"`
	Correlation         *Correlation `json:"correlation,omitempty"`
}

// Pack 是加载后的规则包。
type Pack struct {
	Version string `json:"version"`
	Source  string `json:"source"`
	Rules   []Rule `json:"rules"`

	byID   map[string]*Rule
	bySlug map[string]*Rule
}

var (
	defaultOnce sync.Once
	defaultPack *Pack
	defaultErr  error
)

// Default 返回内嵌规则包（只加载一次）；内嵌包损坏是构建错误。
func Default() (*Pack, error) {
	defaultOnce.Do(func() { defaultPack, defaultErr = Load(embeddedRules) })
	return defaultPack, defaultErr
}

// Load 解析规则包 JSON（导出给测试与调用方做启动前校验）。
func Load(raw []byte) (*Pack, error) {
	var p Pack
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("detections: parse rules: %w", err)
	}
	if len(p.Rules) == 0 {
		return nil, fmt.Errorf("detections: rule pack is empty")
	}
	p.byID = make(map[string]*Rule, len(p.Rules))
	p.bySlug = make(map[string]*Rule, len(p.Rules))
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.ID == "" || r.Slug == "" || r.Title == "" {
			return nil, fmt.Errorf("detections: rule without id/slug/title")
		}
		if _, dup := p.byID[r.ID]; dup {
			return nil, fmt.Errorf("detections: duplicate rule id %s", r.ID)
		}
		if _, dup := p.bySlug[r.Slug]; dup {
			return nil, fmt.Errorf("detections: duplicate rule slug %s", r.Slug)
		}
		if r.Kind != "atomic" && r.Kind != "correlation" {
			return nil, fmt.Errorf("detections: rule %s has unknown kind %q", r.Slug, r.Kind)
		}
		if r.Kind == "correlation" && r.Correlation == nil {
			return nil, fmt.Errorf("detections: correlation rule %s has no correlation spec", r.Slug)
		}
		if r.Kind == "atomic" && len(r.Tokens)+len(r.CaseSensitiveTokens) == 0 {
			return nil, fmt.Errorf("detections: atomic rule %s has no tokens", r.Slug)
		}
		for _, tok := range append(append([]string{}, r.Tokens...), r.CaseSensitiveTokens...) {
			if strings.TrimSpace(tok) == "" {
				return nil, fmt.Errorf("detections: rule %s has an empty token", r.Slug)
			}
		}
		p.byID[r.ID] = r
		p.bySlug[r.Slug] = r
	}
	// 关联规则引用的基规则必须存在（上游要求整棵树一起转换，单文件转不了）。
	for _, r := range p.Rules {
		if r.Correlation == nil {
			continue
		}
		for _, base := range r.Correlation.BaseRuleIDs {
			if _, ok := p.byID[base]; !ok {
				return nil, fmt.Errorf("detections: rule %s references unknown base rule %s", r.Slug, base)
			}
		}
	}
	return &p, nil
}

// ByID 按 Sigma UUID 取规则。
func (p *Pack) ByID(id string) (*Rule, bool) {
	r, ok := p.byID[id]
	return r, ok
}

// BySlug 按短标识取规则。
func (p *Pack) BySlug(slug string) (*Rule, bool) {
	r, ok := p.bySlug[slug]
	return r, ok
}

// AtomicRules 返回全部原子规则（登记时与批量重扫只跑这些）。
func (p *Pack) AtomicRules() []*Rule {
	var out []*Rule
	for i := range p.Rules {
		if p.Rules[i].Kind == "atomic" {
			out = append(out, &p.Rules[i])
		}
	}
	return out
}

// CorrelationRules 返回全部关联规则。
func (p *Pack) CorrelationRules() []*Rule {
	var out []*Rule
	for i := range p.Rules {
		if p.Rules[i].Kind == "correlation" {
			out = append(out, &p.Rules[i])
		}
	}
	return out
}

// FindingEvidence 是一次 finding 匹配的输入视图：调用方填手头已有的字段。
type FindingEvidence struct {
	VulnClass string
	Name      string
	Summary   string
	Evidence  string   // 证据正文（含命令输出、日志片段）
	Packet    string   // 可复现 POC 的原始 HTTP 请求包
	Traffic   []string // 已绑定流量的请求/响应头正文
	Commands  []string // 已记录的执行命令文本
}

// Hit 是一次原子规则命中。
type Hit struct {
	RuleID     string   `json:"rule_id"`
	Slug       string   `json:"slug"`
	Title      string   `json:"title"`
	Level      string   `json:"level"`
	Techniques []string `json:"techniques"`
	Token      string   `json:"token"`   // 命中的 token（TokensAll 时为第一个）
	Scope      string   `json:"scope"`   // 命中的证据范围
	Excerpt    string   `json:"excerpt"` // token 周围上下文（截断）
}

// scopeTexts 按规则的 scopes 拼出待查文本：每个 scope 一份文本，
// TokensAll 要求同一份文本内全部 token 都出现（CA 规则：裸文件名不够）。
func scopeTexts(ev FindingEvidence, scopes []string) [][2]string {
	var out [][2]string
	for _, s := range scopes {
		switch s {
		case "evidence":
			out = append(out, [2]string{"evidence", strings.Join([]string{ev.Name, ev.Summary, ev.Evidence}, "\n")})
		case "traffic":
			out = append(out, [2]string{"traffic", strings.Join(ev.Traffic, "\n")})
		case "packet":
			out = append(out, [2]string{"packet", ev.Packet})
		case "commands":
			out = append(out, [2]string{"commands", strings.Join(ev.Commands, "\n")})
		}
	}
	return out
}

// matchTokens 在一份文本里找 token：大小写不敏感为主，
// CaseSensitiveTokens 只按原样匹配（TRUNCATE：避开小写 truncate 命令）。
// 返回命中的 token 与它在原文中的位置（-1 为未命中）。
func matchTokens(text string, r *Rule) (string, int) {
	lower := strings.ToLower(text)
	if r.TokensAll {
		for _, tok := range r.Tokens {
			if !strings.Contains(lower, strings.ToLower(tok)) {
				return "", -1
			}
		}
		tok := r.Tokens[0]
		return tok, strings.Index(lower, strings.ToLower(tok))
	}
	for _, tok := range r.Tokens {
		if i := strings.Index(lower, strings.ToLower(tok)); i >= 0 {
			return tok, i
		}
	}
	for _, tok := range r.CaseSensitiveTokens {
		if i := strings.Index(text, tok); i >= 0 {
			return tok, i
		}
	}
	return "", -1
}

// excerpt 截取 token 周围的上下文（前后各 80 字符，总长封顶 240）。
func excerpt(text string, at int, tokLen int) string {
	if at < 0 {
		return ""
	}
	start := at - 80
	if start < 0 {
		start = 0
	}
	end := at + tokLen + 80
	if end > len(text) {
		end = len(text)
	}
	s := text[start:end]
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 240 {
		s = s[:240]
	}
	return s
}

// MatchFinding 对一条 finding 跑全部原子规则（enabled 为 nil 时全启用，
// 否则按 Sigma ID 查开关）。每条规则最多一命中，命中顺序按规则包顺序。
func (p *Pack) MatchFinding(ev FindingEvidence, enabled map[string]bool) []Hit {
	var hits []Hit
	for _, r := range p.AtomicRules() {
		if enabled != nil && !enabled[r.ID] {
			continue
		}
		for _, st := range scopeTexts(ev, r.Scopes) {
			scope, text := st[0], st[1]
			if strings.TrimSpace(text) == "" {
				continue
			}
			if tok, at := matchTokens(text, r); at >= 0 {
				hits = append(hits, Hit{
					RuleID:     r.ID,
					Slug:       r.Slug,
					Title:      r.Title,
					Level:      r.Level,
					Techniques: append([]string(nil), r.Techniques...),
					Token:      tok,
					Scope:      scope,
					Excerpt:    excerpt(text, at, len(tok)),
				})
				break
			}
		}
	}
	return hits
}

// MatchRuleText 是原子规则对任意单段文本的匹配（关联评估与工具复用）。
func (p *Pack) MatchRuleText(ruleID, text string) (Hit, bool) {
	r, ok := p.byID[ruleID]
	if !ok || r.Kind != "atomic" {
		return Hit{}, false
	}
	tok, at := matchTokens(text, r)
	if at < 0 {
		return Hit{}, false
	}
	return Hit{RuleID: r.ID, Slug: r.Slug, Title: r.Title, Level: r.Level,
		Techniques: append([]string(nil), r.Techniques...),
		Token:      tok, Excerpt: excerpt(text, at, len(tok))}, true
}

// Event 是关联评估的一条事件：一条已记录的流量/日志，带时间与分组键。
type Event struct {
	Time   time.Time
	Source string // 来源分组键（FORANG 侧操作源，如录制代理宿主）
	Host   string // 目标分组键（被测资产 host）
	Text   string // 事件正文（请求头/日志行）
}

// CorrelationHit 是一次关联规则命中。
type CorrelationHit struct {
	RuleID     string    `json:"rule_id"`
	Slug       string    `json:"slug"`
	Title      string    `json:"title"`
	Level      string    `json:"level"`
	Techniques []string  `json:"techniques"`
	GroupKey   string    `json:"group_key"`
	Count      int       `json:"count"` // 窗内达标计数（value_count 为去重 host 数）
	WindowFrom time.Time `json:"window_from"`
	WindowTo   time.Time `json:"window_to"`
}

func groupKey(e Event, by string) string {
	if by == "host" {
		return e.Host
	}
	return e.Source
}

// EvaluateCorrelations 对一批事件跑全部关联规则。每组最多一命中（取计数最大的窗）。
func (p *Pack) EvaluateCorrelations(events []Event, enabled map[string]bool) []CorrelationHit {
	var hits []CorrelationHit
	for _, r := range p.CorrelationRules() {
		if enabled != nil && !enabled[r.ID] {
			continue
		}
		c := r.Correlation
		// 先算每条事件命中了哪些基规则。
		matched := make([]map[string]bool, len(events))
		for i, e := range events {
			m := map[string]bool{}
			for _, base := range c.BaseRuleIDs {
				if _, ok := p.MatchRuleText(base, e.Text); ok {
					m[base] = true
				}
			}
			matched[i] = m
		}
		groups := map[string][]int{}
		for i, e := range events {
			groups[groupKey(e, c.GroupBy)] = append(groups[groupKey(e, c.GroupBy)], i)
		}
		keys := make([]string, 0, len(groups))
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			idxs := groups[k]
			sort.Slice(idxs, func(a, b int) bool { return events[idxs[a]].Time.Before(events[idxs[b]].Time) })
			window := time.Duration(c.TimespanMinutes) * time.Minute
			best := 0
			var bestFrom, bestTo time.Time
			switch c.Type {
			case "event_count":
				// 滑窗：窗内命中任一基规则的事件数。
				for a := 0; a < len(idxs); a++ {
					count := 0
					for b := a; b < len(idxs); b++ {
						if events[idxs[b]].Time.Sub(events[idxs[a]].Time) > window {
							break
						}
						if len(matched[idxs[b]]) > 0 {
							count++
						}
					}
					if count > best {
						best, bestFrom, bestTo = count, events[idxs[a]].Time, events[idxs[a]].Time.Add(window)
					}
				}
			case "value_count":
				// 滑窗：窗内命中事件去重后的 Field 值个数。
				for a := 0; a < len(idxs); a++ {
					seen := map[string]bool{}
					for b := a; b < len(idxs); b++ {
						if events[idxs[b]].Time.Sub(events[idxs[a]].Time) > window {
							break
						}
						if len(matched[idxs[b]]) > 0 {
							seen[events[idxs[b]].Host] = true
						}
					}
					if len(seen) > best {
						best, bestFrom, bestTo = len(seen), events[idxs[a]].Time, events[idxs[a]].Time.Add(window)
					}
				}
			case "temporal":
				// 每条基规则在同一窗内至少命中一次。
				for a := 0; a < len(idxs); a++ {
					seen := map[string]bool{}
					for b := a; b < len(idxs); b++ {
						if events[idxs[b]].Time.Sub(events[idxs[a]].Time) > window {
							break
						}
						for base := range matched[idxs[b]] {
							seen[base] = true
						}
					}
					if len(seen) == len(c.BaseRuleIDs) && len(seen) > best {
						best, bestFrom, bestTo = len(seen), events[idxs[a]].Time, events[idxs[a]].Time.Add(window)
					}
				}
			}
			if best >= c.Threshold {
				hits = append(hits, CorrelationHit{
					RuleID: r.ID, Slug: r.Slug, Title: r.Title, Level: r.Level,
					Techniques: append([]string(nil), r.Techniques...),
					GroupKey:   k, Count: best, WindowFrom: bestFrom, WindowTo: bestTo,
				})
			}
		}
	}
	return hits
}
