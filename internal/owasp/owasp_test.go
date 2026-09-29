package owasp

import (
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

func TestMapRule(t *testing.T) {
	cases := []struct {
		ruleID string
		want   string
	}{
		{"CmdInjection01", "MCP05:2025"},
		{"TokenLeak01", "MCP01:2025"},
		{"ToolPoisoning01", "MCP03:2025"},
		{"HttpAuthBypass01", "MCP07:2025"},
		{"ContextSharing01", "MCP10:2025"},
		{"PromptInjectionReflection", "MCP06:2025"},
		{"StateDesync01", ""},
		{"AttackChain01", ""},
		{"UnknownRule", ""},
	}
	for _, tc := range cases {
		if got := MapRule(tc.ruleID); got != tc.want {
			t.Errorf("MapRule(%s) = %q, want %q", tc.ruleID, got, tc.want)
		}
	}
}

func TestCoverageSummaryCountsFindings(t *testing.T) {
	findings := []auditor.Finding{
		{RuleID: "CmdInjection01"},
		{RuleID: "CmdInjection01"},
		{RuleID: "TokenLeak01"},
		{RuleID: "StateDesync01"},
	}
	coverage := CoverageSummary(findings)
	if len(coverage) != 10 {
		t.Fatalf("expected 10 coverage items, got %d", len(coverage))
	}
	counts := map[string]int{}
	for _, item := range coverage {
		counts[item.ID] = item.Findings
	}
	if counts["MCP05:2025"] != 2 {
		t.Errorf("expected 2 findings for MCP05, got %d", counts["MCP05:2025"])
	}
	if counts["MCP01:2025"] != 1 {
		t.Errorf("expected 1 finding for MCP01, got %d", counts["MCP01:2025"])
	}
	if counts["MCP03:2025"] != 0 {
		t.Errorf("expected 0 findings for MCP03, got %d", counts["MCP03:2025"])
	}
}

func TestCoverageSummaryHasStatuses(t *testing.T) {
	coverage := CoverageSummary(nil)
	statuses := map[string]bool{}
	for _, item := range coverage {
		statuses[item.Status] = true
	}
	if !statuses["covered"] || !statuses["partial"] {
		t.Errorf("expected covered and partial statuses, got %+v", statuses)
	}
	if statuses["planned"] {
		t.Error("no risk may remain in planned state after the Depth release")
	}
}
