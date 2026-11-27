package db

// finding_evidence_grade.go — 证据分级（Pojun L1–L4 移植，v0.6.4）。
//
// Pojun 把 finding 的可信度拆成可检查的层级，而不是一个模型自报的 severity：
//   L1 线索/指纹：版本号、报错信息、目录存在、配置暴露
//   L2 行为异常：响应差异、状态码变化、反射/回显、越权对照
//   L3 可利用性：注入回显、命令执行输出、文件读取、登录成功
//   L4 业务影响：读取非授权数据、获取凭据、横向、资金/订单影响
//
// 移植要点（对照 Pojun README §4 与 pojun-skill v2.0）：
//   - critical/high 必须达到 L3+，否则只能作为线索/低置信度，不进交付报告
//     （FORANG 的实现：report_excluded=true，报告里单列「未达交付标准」区，
//     不静默丢弃）；
//   - 分级是确定性启发式（关键词 + 流量绑定角色），不调 LLM，不依赖模型自评；
//   - worker 自报的 evidence_level 只作声明，生效等级 = min(自报, 实测)
//     —— 自报 L4 但拿不出 L4 证据时以实测为准，防止等级虚报；
//   - 只有代码推断（文件:行号、源码行）而无执行回显时最高 L2（Pojun：
//     「代码级证据 + 实际回显 = 高可信；只有代码推断最多 medium」）。
//
// 流量绑定的抬级（FORANG 已有 baseline/proof/verification/supporting 四类）：
//   proof 绑定 → 至少 L3；verification 绑定 → 至少 L2；baseline 仅作对照不抬级。

import (
	"strings"
)

// Evidence levels (findings.evidence_level). "" = 未分级（v0.6.4 之前的旧行）。
const (
	EvidenceL1 = "L1"
	EvidenceL2 = "L2"
	EvidenceL3 = "L3"
	EvidenceL4 = "L4"
)

// ValidEvidenceLevel reports whether s is a known evidence level.
func ValidEvidenceLevel(s string) bool {
	switch s {
	case EvidenceL1, EvidenceL2, EvidenceL3, EvidenceL4:
		return true
	}
	return false
}

// EvidenceLevelLabel renders the level for UI/report badges.
func EvidenceLevelLabel(level string) string {
	switch level {
	case EvidenceL1:
		return "L1 线索"
	case EvidenceL2:
		return "L2 行为异常"
	case EvidenceL3:
		return "L3 可利用"
	case EvidenceL4:
		return "L4 业务影响"
	}
	return "未分级"
}

// EvidenceConfidence maps a level to the confidence label stored alongside it.
func EvidenceConfidence(level string) string {
	switch level {
	case EvidenceL1:
		return "low"
	case EvidenceL2:
		return "medium"
	case EvidenceL3, EvidenceL4:
		return "high"
	}
	return ""
}

func evidenceLevelRank(level string) int {
	switch level {
	case EvidenceL1:
		return 1
	case EvidenceL2:
		return 2
	case EvidenceL3:
		return 3
	case EvidenceL4:
		return 4
	}
	return 0
}

// EffectiveEvidenceLevel returns the level that actually applies: the declared
// level capped by the measured one, so a self-reported L4 with only L1
// evidence counts as L1. Empty declared means "auto-grade".
func EffectiveEvidenceLevel(declared, measured string) string {
	declared = strings.ToUpper(strings.TrimSpace(declared))
	measured = strings.ToUpper(strings.TrimSpace(measured))
	if !ValidEvidenceLevel(declared) {
		return measured
	}
	if !ValidEvidenceLevel(measured) {
		return declared
	}
	if evidenceLevelRank(declared) <= evidenceLevelRank(measured) {
		return declared
	}
	return measured
}

// ReportExcludedForGrade implements the Pojun delivery gate: critical/high
// findings below L3 do not enter the formal report (they are listed separately
// with their level, never silently dropped).
func ReportExcludedForGrade(severity, level string) bool {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case SeverityCritical, SeverityHigh:
		return evidenceLevelRank(level) < 3
	}
	return false
}

// EvidenceGateReason explains why a finding is excluded from the formal report.
func EvidenceGateReason(severity, level string) string {
	if !ReportExcludedForGrade(severity, level) {
		return ""
	}
	return "critical/high 须 L3+ 证据，实测 " + EvidenceLevelLabel(level) + "，未达交付标准"
}

var (
	// L4：业务影响——非授权数据、凭据、横向、资金/订单。须是明确的影响描述，
	// 不能是「可能」「疑似」。
	evidenceL4Markers = []string{
		"非授权数据", "未授权数据", "读取他人", "读取其他用户", "越权读取", "获取凭据",
		"凭据泄露", "凭证泄露", "横向移动", "横向渗透", "资金", "订单", "提现", "支付",
		"lateral movement", "credential", "unauthorized data", "exfiltrat",
	}
	// L3：可利用性——注入回显、命令执行、文件读取、登录成功。
	evidenceL3Markers = []string{
		"命令执行", "注入回显", "文件读取", "登录成功", "成功登录", "命令输出",
		"command execut", "file read", "login success", "logged in",
		"root:", "uid=", "whoami", "sleep(", "benchmark(", "sql 注入成功",
		"sqli", "注入成功", "rce", "远程命令执行", "任意文件读取",
		"ssrf", "服务端请求伪造", "反弹 shell",
	}
	// L2：行为异常——响应差异、状态码变化、反射、越权对照。
	evidenceL2Markers = []string{
		"响应差异", "状态码变化", "状态码不同", "反射", "回显", "越权对照",
		"a/b 对照", "双身份", "response diff", "status code", "reflected",
		"403", "401", "越权", "未授权访问",
	}
	// L1：线索/指纹——版本、报错、目录存在、配置暴露。
	evidenceL1Markers = []string{
		"版本号", "版本信息", "报错信息", "目录存在", "配置暴露", "敏感文件",
		"version", "error message", "stack trace",
	}
	// 只有代码推断：文件:行号、源码行，无执行回显时最高 L2。
	evidenceCodeOnlyMarkers = []string{
		"源码", "代码审计", "source code", ".go:", ".java:", ".py:", ".php:", ".js:",
	}
)

// GradeEvidence auto-grades a finding from its text corpus (name + summary +
// evidence + packet) and its bound traffic roles. hasProof/hasVerification
// come from the traffic bindings being recorded in the same transaction.
// vulnClass is accepted for call-site symmetry but deliberately NOT part of
// the corpus: a category label alone ("SSRF", "SQLi") is not evidence.
func GradeEvidence(vulnClass, name, summary, evidence, packet string, hasProof, hasVerification bool) string {
	_ = vulnClass
	corpus := strings.ToLower(strings.Join([]string{name, summary, evidence, packet}, "\n"))
	contains := func(markers []string) bool {
		for _, m := range markers {
			if strings.Contains(corpus, strings.ToLower(m)) {
				return true
			}
		}
		return false
	}
	level := EvidenceL1
	if contains(evidenceL1Markers) {
		level = EvidenceL1
	}
	if contains(evidenceL2Markers) {
		level = EvidenceL2
	}
	if hasVerification && evidenceLevelRank(level) < 2 {
		level = EvidenceL2
	}
	// 只有代码推断（文件:行号、源码行）而无执行回显时最高 L2，但代码定位本身
	// 已是具体线索，至少 L2（Pojun：「只有代码推断最多 medium」）。
	codeOnly := contains(evidenceCodeOnlyMarkers) && !contains(evidenceL3Markers) && !contains(evidenceL4Markers)
	if codeOnly && evidenceLevelRank(level) < 2 {
		level = EvidenceL2
	}
	if contains(evidenceL3Markers) || hasProof {
		if codeOnly && !hasProof {
			level = EvidenceL2
		} else {
			level = EvidenceL3
		}
	}
	if contains(evidenceL4Markers) {
		level = EvidenceL4
	}
	return level
}
