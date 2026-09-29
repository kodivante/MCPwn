package attackchain

import (
	"strings"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

func cmdInjection(tool string) auditor.Finding {
	return auditor.Finding{RuleID: "CmdInjection01", TargetTool: tool, Severity: auditor.SeverityCritical}
}

func tokenLeak(tool string) auditor.Finding {
	return auditor.Finding{RuleID: "TokenLeak01", TargetTool: tool, Severity: auditor.SeverityCritical}
}

func ssrf(tool string) auditor.Finding {
	return auditor.Finding{RuleID: "Ssrf01", TargetTool: tool, Severity: auditor.SeverityHigh}
}

func TestAnalyzeDetectsRceChain(t *testing.T) {
	detector := NewDetector()
	findings := []auditor.Finding{cmdInjection("exec"), tokenLeak("exec")}
	results := detector.Analyze(findings)
	if len(results) != 3 {
		t.Fatalf("expected 3 results (2 findings + 1 chain), got %d", len(results))
	}
	chain := results[2]
	if chain.RuleID != "AttackChain01" {
		t.Errorf("expected AttackChain01, got %s", chain.RuleID)
	}
	if chain.Severity != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL chain, got %s", chain.Severity)
	}
	if !strings.Contains(chain.Evidence, "CmdInjection01") || !strings.Contains(chain.Evidence, "TokenLeak01") {
		t.Errorf("expected both links in evidence, got %s", chain.Evidence)
	}
}

func TestAnalyzeNoChainWithoutPairs(t *testing.T) {
	detector := NewDetector()
	findings := []auditor.Finding{cmdInjection("exec")}
	results := detector.Analyze(findings)
	if len(results) != 1 {
		t.Errorf("expected 1 result without pairs, got %d", len(results))
	}
}

func TestAnalyzeSsrfExfilChain(t *testing.T) {
	detector := NewDetector()
	findings := []auditor.Finding{ssrf("fetch"), tokenLeak("fetch")}
	results := detector.Analyze(findings)
	if len(results) != 3 {
		t.Fatalf("expected chain detection for SSRF+leak, got %d results", len(results))
	}
	if results[2].Severity != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", results[2].Severity)
	}
}

func TestAnalyzePreservesOriginals(t *testing.T) {
	detector := NewDetector()
	findings := []auditor.Finding{cmdInjection("a"), tokenLeak("b"), ssrf("c")}
	results := detector.Analyze(findings)
	if results[0].RuleID != "CmdInjection01" || results[1].RuleID != "TokenLeak01" || results[2].RuleID != "Ssrf01" {
		t.Error("original findings must be preserved in order")
	}
	if len(results) < 4 {
		t.Errorf("expected at least 1 chain for 3 findings, got %d", len(results))
	}
}

func TestAllPresent(t *testing.T) {
	present := map[string]bool{"a": true, "b": true}
	if !allPresent([]string{"a", "b"}, present) {
		t.Error("expected all present")
	}
	if allPresent([]string{"a", "c"}, present) {
		t.Error("expected missing link to fail")
	}
}

func TestFormatLinks(t *testing.T) {
	links := []chainLink{{RuleID: "A01", Reason: "A01 on toolA"}, {RuleID: "B01", Reason: "B01 on toolB"}}
	got := formatLinks(links)
	if !strings.Contains(got, "A01 (") || !strings.Contains(got, "-> B01") {
		t.Errorf("unexpected format: %s", got)
	}
}
