package correlation

import (
	"strings"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/taint"
)

func TestCorrelateStaticAndRuntimeEvidence(t *testing.T) {
	paths := []taint.Path{{
		Tool:      "runReport",
		Entry:     "runReport(cmd)",
		SinkClass: "exec",
		Hops: []taint.Hop{
			{Function: "runReport", File: "server.py", Line: 9},
			{Function: "executeShell", File: "server.py", Line: 11},
			{Function: "os.system", File: "server.py", Line: 17},
		},
	}}
	findings := []auditor.Finding{
		{RuleID: "CmdInjection01", TargetTool: "runReport", Severity: auditor.SeverityCritical, Confirmed: true, Evidence: "marker returned in response"},
		{RuleID: "CmdInjection01", TargetTool: "otherTool", Severity: auditor.SeverityCritical, Confirmed: false},
	}
	correlations := Correlate(findings, paths)
	if len(correlations) != 1 {
		t.Fatalf("expected 1 correlation, got %+v", correlations)
	}
	first := correlations[0]
	if first.RuleID != "CorrelatedVuln01" || first.TargetTool != "runReport" {
		t.Errorf("unexpected correlation: %+v", first)
	}
	if first.Severity != auditor.SeverityCritical || !first.Confirmed {
		t.Errorf("correlation must be CRITICAL and confirmed: %+v", first)
	}
	if !strings.Contains(first.Evidence, "static path: runReport") || !strings.Contains(first.Evidence, "CmdInjection01") {
		t.Errorf("expected merged evidence, got: %s", first.Evidence)
	}
}

func TestCorrelateRequiresConfirmedRuntime(t *testing.T) {
	paths := []taint.Path{{Tool: "runReport", SinkClass: "exec"}}
	findings := []auditor.Finding{
		{RuleID: "CmdInjection01", TargetTool: "runReport", Confirmed: false},
	}
	if correlations := Correlate(findings, paths); len(correlations) != 0 {
		t.Errorf("unconfirmed runtime must not correlate, got %+v", correlations)
	}
}

func TestCorrelateRequiresSameTool(t *testing.T) {
	paths := []taint.Path{{Tool: "runReport", SinkClass: "exec"}}
	findings := []auditor.Finding{
		{RuleID: "CmdInjection01", TargetTool: "differentTool", Confirmed: true},
	}
	if correlations := Correlate(findings, paths); len(correlations) != 0 {
		t.Errorf("cross-tool findings must not correlate, got %+v", correlations)
	}
}

func TestCorrelateNetworkClass(t *testing.T) {
	paths := []taint.Path{{Tool: "fetchConfig", SinkClass: "network"}}
	findings := []auditor.Finding{
		{RuleID: "Ssrf01", TargetTool: "fetchConfig", Confirmed: true, Evidence: "canary hit"},
	}
	correlations := Correlate(findings, paths)
	if len(correlations) != 1 || correlations[0].TargetTool != "fetchConfig" {
		t.Fatalf("expected network correlation, got %+v", correlations)
	}
}

func TestCorrelateDeduplicatesPerToolAndClass(t *testing.T) {
	paths := []taint.Path{
		{Tool: "runReport", SinkClass: "exec"},
		{Tool: "runReport", SinkClass: "exec"},
	}
	findings := []auditor.Finding{
		{RuleID: "CmdInjection01", TargetTool: "runReport", Confirmed: true},
		{RuleID: "MutationDiff01", TargetTool: "runReport", Confirmed: true},
	}
	if correlations := Correlate(findings, paths); len(correlations) != 1 {
		t.Errorf("expected deduplicated correlation, got %d", len(correlations))
	}
}

func TestCorrelateNoPaths(t *testing.T) {
	findings := []auditor.Finding{{RuleID: "CmdInjection01", TargetTool: "x", Confirmed: true}}
	if correlations := Correlate(findings, nil); len(correlations) != 0 {
		t.Errorf("expected no correlation without paths, got %+v", correlations)
	}
}
