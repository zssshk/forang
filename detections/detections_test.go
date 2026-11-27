package detections

import (
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/knowledge"
)

func mustPack(t *testing.T) *Pack {
	t.Helper()
	p, err := Default()
	if err != nil {
		t.Fatalf("load pack: %v", err)
	}
	return p
}

func TestPackCounts(t *testing.T) {
	p := mustPack(t)
	if len(p.Rules) != 9 {
		t.Fatalf("rules = %d, want 9", len(p.Rules))
	}
	if len(p.AtomicRules()) != 5 {
		t.Fatalf("atomic = %d, want 5", len(p.AtomicRules()))
	}
	if len(p.CorrelationRules()) != 4 {
		t.Fatalf("correlation = %d, want 4", len(p.CorrelationRules()))
	}
	techs := map[string]bool{}
	for _, r := range p.Rules {
		techs[r.Techniques[0]] = true
		for _, tech := range r.Techniques {
			techs[tech] = true
		}
	}
	// 上游 ATT&CK 层 8 个技术（T1561 只作父级展示，不计分）。
	want := []string{"T1595", "T1592", "T1105", "T1059", "T1485", "T1561.002", "T1489", "T1557"}
	for _, tech := range want {
		if !techs[tech] {
			t.Errorf("technique %s missing from pack", tech)
		}
	}
}

// TestTechniquesResolveInKnowledgePack：规则的 ATT&CK 编号必须与 v0.6.2
// knowledge-pack（ATT&CK 706）同源，不另起一套编号。
func TestTechniquesResolveInKnowledgePack(t *testing.T) {
	p := mustPack(t)
	kp, err := knowledge.Default()
	if err != nil {
		t.Fatalf("knowledge pack: %v", err)
	}
	for _, r := range p.Rules {
		for _, tech := range r.Techniques {
			if _, ok := kp.Lookup("attack", tech); !ok {
				t.Errorf("rule %s technique %s not in knowledge-pack", r.Slug, tech)
			}
		}
	}
}

func TestMatchFindingAtomic(t *testing.T) {
	p := mustPack(t)
	cases := []struct {
		name  string
		ev    FindingEvidence
		want  []string // 命中的 slug
		avoid []string // 不应命中的 slug
	}{
		{
			name: "enrich UA in packet",
			ev: FindingEvidence{Packet: "GET / HTTP/1.1\nHost: example.com\nUser-Agent: artex-enrich/1.0\n\n",
				VulnClass: "Information Disclosure"},
			want: []string{"enrich-user-agent"},
		},
		{
			name: "forang selfupdate UA (adapted token)",
			ev:   FindingEvidence{Traffic: []string{"GET https://github.com/releases HTTP/1.1\nUser-Agent: forang-selfupdate"}},
			want: []string{"selfupdate-egress"},
		},
		{
			name: "upstream artex-selfupdate must NOT match (FORANG renamed it)",
			ev:   FindingEvidence{Traffic: []string{"User-Agent: artex-selfupdate"}},
			want: []string{},
		},
		{
			name: "guard marker in evidence",
			ev:   FindingEvidence{Evidence: "工具调用被拦：【ARTEX 平台管控·非目标防御】此调用被平台拦截。"},
			want: []string{"guard-audit-framing"},
		},
		{
			name: "destructive DROP TABLE in evidence",
			ev:   FindingEvidence{Evidence: "验证：'; DROP TABLE users; -- 回显成功", VulnClass: "SQL Injection"},
			want: []string{"destructive-command-hunting"},
		},
		{
			name: "destructive rm -rf in commands",
			ev:   FindingEvidence{Commands: []string{"rm -rf /tmp/test"}, VulnClass: "Remote Code Execution"},
			want: []string{"destructive-command-hunting"},
		},
		{
			name: "CA rule needs both tokens",
			ev:   FindingEvidence{Evidence: "写入 data/traffic/_ca/mitmproxy-ca-cert.pem 并注入 CA"},
			want: []string{"recording-proxy-ca"},
		},
		{
			name:  "bare CA filename alone must NOT trip the CA rule",
			ev:    FindingEvidence{Evidence: "本机 ~/.mitmproxy/mitmproxy-ca-cert.pem 是开发用的"},
			want:  []string{},
			avoid: []string{"recording-proxy-ca"},
		},
		{
			name:  "lowercase truncate command must NOT trip destructive rule",
			ev:    FindingEvidence{Commands: []string{"truncate -s 0 /var/log/app.log"}},
			want:  []string{},
			avoid: []string{"destructive-command-hunting"},
		},
		{
			name: "benign finding has no hits",
			ev: FindingEvidence{VulnClass: "Information Disclosure", Summary: "服务器返回版本头",
				Evidence: "响应头 Server: nginx/1.24", Packet: "GET / HTTP/1.1\nHost: x\nUser-Agent: curl/8.0\n\n"},
			want: []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := p.MatchFinding(tc.ev, nil)
			got := map[string]bool{}
			for _, h := range hits {
				got[h.Slug] = true
			}
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("want hit %s, got %v", w, hits)
				}
			}
			for _, a := range tc.avoid {
				if got[a] {
					t.Errorf("must not hit %s, got %v", a, hits)
				}
			}
			if len(tc.want) == 0 && len(hits) != 0 {
				t.Errorf("want no hits, got %v", hits)
			}
		})
	}
}

func TestMatchFindingDisabledRule(t *testing.T) {
	p := mustPack(t)
	ev := FindingEvidence{Packet: "User-Agent: artex-enrich/1.0"}
	enabled := map[string]bool{"34adfa15-1696-4322-afc0-f69988e9cc1e": false}
	if hits := p.MatchFinding(ev, enabled); len(hits) != 0 {
		t.Fatalf("disabled rule still matched: %v", hits)
	}
}

func mkEvents(n int, start time.Time, step time.Duration, source, host, text string) []Event {
	evs := make([]Event, n)
	for i := range evs {
		evs[i] = Event{Time: start.Add(time.Duration(i) * step), Source: source, Host: host, Text: text}
	}
	return evs
}

func TestEvaluateCorrelations(t *testing.T) {
	p := mustPack(t)
	base := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	enrichText := "GET / HTTP/1.1\nUser-Agent: artex-enrich/1.0"
	guardText := "【ARTEX 平台管控·非目标防御】此调用被平台拦截。"
	destrText := "rm -rf /tmp/x"

	// 速率：30 次/5 分钟达标，29 次不达标。
	evs := mkEvents(30, base, 10*time.Second, "forang-host", "target-a", enrichText)
	if hits := p.EvaluateCorrelations(evs, nil); !hasSlug(hits, "enrich-scan-velocity") {
		t.Errorf("velocity 30 events: want hit, got %v", hits)
	}
	evs = mkEvents(29, base, 10*time.Second, "forang-host", "target-a", enrichText)
	if hits := p.EvaluateCorrelations(evs, nil); hasSlug(hits, "enrich-scan-velocity") {
		t.Errorf("velocity 29 events: must not hit, got %v", hits)
	}
	// 扇出：20 个不同 host 达标；同一 host 30 次不达标。
	var fan []Event
	for i := 0; i < 20; i++ {
		fan = append(fan, Event{Time: base.Add(time.Duration(i) * 10 * time.Second),
			Source: "forang-host", Host: "target-" + strings.Repeat("x", i+1), Text: enrichText})
	}
	if hits := p.EvaluateCorrelations(fan, nil); !hasSlug(hits, "enrich-fanout") {
		t.Errorf("fanout 20 hosts: want hit, got %v", hits)
	}
	// 封锁突发：5 次 guard 标记/10 分钟达标。
	evs = mkEvents(5, base, 2*time.Minute, "forang-host", "target-a", guardText)
	if hits := p.EvaluateCorrelations(evs, nil); !hasSlug(hits, "guard-block-burst") {
		t.Errorf("guard burst 5: want hit, got %v", hits)
	}
	// guard 标记 + 破坏性命令同窗 30 分钟达标；超出窗不达标。
	evs = []Event{
		{Time: base, Source: "forang-host", Host: "target-a", Text: guardText},
		{Time: base.Add(10 * time.Minute), Source: "forang-host", Host: "target-a", Text: destrText},
	}
	if hits := p.EvaluateCorrelations(evs, nil); !hasSlug(hits, "guard-marker-then-destructive") {
		t.Errorf("marker+destructive in window: want hit, got %v", hits)
	}
	evs = []Event{
		{Time: base, Source: "forang-host", Host: "target-a", Text: guardText},
		{Time: base.Add(31 * time.Minute), Source: "forang-host", Host: "target-a", Text: destrText},
	}
	if hits := p.EvaluateCorrelations(evs, nil); hasSlug(hits, "guard-marker-then-destructive") {
		t.Errorf("marker+destructive outside window: must not hit, got %v", hits)
	}
}

func hasSlug(hits []CorrelationHit, slug string) bool {
	for _, h := range hits {
		if h.Slug == slug {
			return true
		}
	}
	return false
}

func TestSortReviewQueue(t *testing.T) {
	now := time.Now()
	items := []ReviewItem{
		{FindingID: 1, Severity: "high", EvidenceLevel: "L3", HitCount: 0, CreatedAt: now},
		{FindingID: 2, Severity: "critical", EvidenceLevel: "L2", HitCount: 0, CreatedAt: now},
		{FindingID: 3, Severity: "high", EvidenceLevel: "L4", HitCount: 0, CreatedAt: now},
		{FindingID: 4, Severity: "high", EvidenceLevel: "L3", HitCount: 2, CreatedAt: now},
		{FindingID: 5, Severity: "high", EvidenceLevel: "L3", HitCount: 1, CreatedAt: now.Add(time.Hour)},
	}
	SortReviewQueue(items)
	want := []int64{2, 3, 4, 5, 1}
	for i, id := range want {
		if items[i].FindingID != id {
			t.Fatalf("position %d: got finding %d, want %d (order %v)", i, items[i].FindingID, id, items)
		}
	}
}

func TestCoverage(t *testing.T) {
	p := mustPack(t)
	rep := p.Coverage(nil, []string{"SQL Injection", "Remote Code Execution", "Something Entirely New"})
	if len(rep.UncoveredTechniques) != 0 {
		t.Errorf("all techniques should be covered, uncovered: %v", rep.UncoveredTechniques)
	}
	byClass := map[string]ClassCoverage{}
	for _, c := range rep.Classes {
		byClass[c.Class] = c
	}
	if !byClass["SQL Injection"].Covered {
		t.Errorf("SQL Injection should be covered by destructive rule")
	}
	if byClass["Something Entirely New"].Covered {
		t.Errorf("unknown class must be uncovered")
	}
	if len(rep.UncoveredClasses) != 1 || rep.UncoveredClasses[0] != "Something Entirely New" {
		t.Errorf("uncovered classes = %v", rep.UncoveredClasses)
	}
	// 禁用破坏性规则后，SQL Injection 应变无覆盖。
	enabled := map[string]bool{"f510564f-2958-4dc8-a188-3300a2f6f5a7": false}
	rep = p.Coverage(enabled, []string{"SQL Injection"})
	if rep.Classes[0].Covered {
		t.Errorf("SQL Injection should be uncovered once destructive rule is disabled")
	}
}
