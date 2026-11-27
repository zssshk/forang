package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestPartitionReportFindings covers the v0.6.4 evidence gate at the report
// layer: report_excluded findings never enter the main body — they are
// returned separately for the "未达交付标准" section, never silently dropped.
func TestPartitionReportFindings(t *testing.T) {
	fs := []*db.DBFinding{
		{Severity: "high", EvidenceLevel: "L3"},
		{Severity: "high", EvidenceLevel: "L1", ReportExcluded: true},
		{Severity: "medium", EvidenceLevel: "L1"},
		{Severity: "critical", EvidenceLevel: "", ReportExcluded: true},
	}
	in, ex := partitionReportFindings(fs)
	if len(in) != 2 || len(ex) != 2 {
		t.Fatalf("in=%d ex=%d, want 2/2", len(in), len(ex))
	}
	for _, f := range in {
		if f.ReportExcluded {
			t.Fatalf("reportable set contains excluded finding: %+v", f)
		}
	}
	for _, f := range ex {
		if !f.ReportExcluded {
			t.Fatalf("excluded set contains reportable finding: %+v", f)
		}
	}
	// Empty input partitions to two empty (non-nil-dependence-free) slices.
	in, ex = partitionReportFindings(nil)
	if len(in) != 0 || len(ex) != 0 {
		t.Fatalf("nil input: in=%d ex=%d", len(in), len(ex))
	}
}
