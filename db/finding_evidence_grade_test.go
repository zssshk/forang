package db

import "testing"

// TestEvidenceGrading covers the Pojun L1–L4 port (v0.6.4): deterministic
// grading from evidence text + traffic roles, the declared-vs-measured cap,
// and the critical/high delivery gate. Pure functions — no postgres needed.
func TestEvidenceGrading(t *testing.T) {
	cases := []struct {
		name       string
		summary    string
		evidence   string
		packet     string
		proof      bool
		verify     bool
		declared   string
		wantLevel  string
		wantConf   string
		wantExclHi bool // report_excluded for severity=high
	}{
		{"L1 version fingerprint only", "版本泄露", "服务器返回版本号 Apache 2.4.49", "", false, false, "", "L1", "low", true},
		{"L2 response diff", "越权访问", "A 身份返回 200，B 身份返回 403，响应差异明显", "", false, false, "", "L2", "medium", true},
		{"L2 verification traffic", "可疑接口", "已核实", "", false, true, "", "L2", "medium", true},
		{"L3 command execution", "命令注入", "命令执行成功，输出 uid=0(root)", "", false, false, "", "L3", "high", false},
		{"L3 proof traffic lifts", "SQL 注入", "注入点已确认", "", true, false, "", "L3", "high", false},
		{"L4 business impact", "越权读订单", "非授权数据：读取他人订单与支付信息", "", false, false, "", "L4", "high", false},
		{"code only caps at L2", "硬编码密钥", "源码 .go:123 发现硬编码密钥，未验证能否使用", "", false, false, "", "L2", "medium", true},
		{"declared L4 capped by measured L1", "版本泄露", "服务器返回版本号", "", false, false, "L4", "L1", "low", true},
		{"declared L2 below measured L3", "命令注入", "命令执行成功，输出 uid=0(root)", "", false, false, "L2", "L2", "medium", true},
		{"medium severity never excluded", "版本泄露", "服务器返回版本号", "", false, false, "", "L1", "low", false},
	}
	for _, tc := range cases {
		measured := GradeEvidence("XSS", tc.name, tc.summary, tc.evidence, tc.packet, tc.proof, tc.verify)
		got := EffectiveEvidenceLevel(tc.declared, measured)
		if got != tc.wantLevel {
			t.Errorf("%s: level=%s want %s (measured %s, declared %q)", tc.name, got, tc.wantLevel, measured, tc.declared)
		}
		if c := EvidenceConfidence(got); c != tc.wantConf {
			t.Errorf("%s: confidence=%s want %s", tc.name, c, tc.wantConf)
		}
		sev := "high"
		if tc.wantExclHi == false && tc.name == "medium severity never excluded" {
			sev = "medium"
		}
		if ex := ReportExcludedForGrade(sev, got); ex != tc.wantExclHi {
			t.Errorf("%s: report_excluded(%s)=%v want %v", tc.name, sev, ex, tc.wantExclHi)
		}
	}
}

func TestEvidenceLevelLabels(t *testing.T) {
	for _, lv := range []string{"L1", "L2", "L3", "L4"} {
		if !ValidEvidenceLevel(lv) {
			t.Errorf("%s should be valid", lv)
		}
		if EvidenceLevelLabel(lv) == "未分级" {
			t.Errorf("%s should have a label", lv)
		}
	}
	if ValidEvidenceLevel("L5") || ValidEvidenceLevel("") {
		t.Error("L5/empty must be invalid")
	}
	if got := EvidenceGateReason("high", "L2"); got == "" {
		t.Error("high+L2 must have a gate reason")
	}
	if got := EvidenceGateReason("high", "L3"); got != "" {
		t.Errorf("high+L3 must have no gate reason, got %q", got)
	}
}
