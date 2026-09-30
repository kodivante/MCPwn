package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("policy write failed: %v", err)
	}
	return path
}

func TestLoad(t *testing.T) {
	path := writePolicy(t, `{"failOn":["critical","high"],"maxFindings":10,"ignoreRules":["SchemaValidation01"]}`)
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if len(loaded.FailOn) != 2 || loaded.MaxFindings != 10 || len(loaded.IgnoreRules) != 1 {
		t.Errorf("unexpected policy: %+v", loaded)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("expected error for missing policy")
	}
}

func TestEvaluateSeverityGate(t *testing.T) {
	target := Policy{FailOn: []string{"CRITICAL", "HIGH"}}
	findings := []auditor.Finding{
		{RuleID: "CmdInjection01", Severity: auditor.SeverityCritical},
		{RuleID: "Ssrf01", Severity: auditor.SeverityMedium},
	}
	violations, fail := Evaluate(target, findings)
	if !fail {
		t.Fatal("expected failure on critical findings")
	}
	if len(violations) != 1 || !strings.Contains(violations[0].Detail, "CRITICAL") {
		t.Errorf("unexpected violations: %+v", violations)
	}
}

func TestEvaluateCleanAuditPasses(t *testing.T) {
	target := Policy{FailOn: []string{"CRITICAL", "HIGH"}}
	findings := []auditor.Finding{
		{RuleID: "WeakTyping01", Severity: auditor.SeverityLow},
	}
	violations, fail := Evaluate(target, findings)
	if fail {
		t.Errorf("expected pass, got violations %+v", violations)
	}
}

func TestEvaluateFindingsGate(t *testing.T) {
	target := Policy{MaxFindings: 2}
	findings := []auditor.Finding{
		{RuleID: "A", Severity: auditor.SeverityLow},
		{RuleID: "B", Severity: auditor.SeverityLow},
		{RuleID: "C", Severity: auditor.SeverityLow},
	}
	violations, fail := Evaluate(target, findings)
	if !fail || len(violations) != 1 || violations[0].Kind != "findings-gate" {
		t.Fatalf("expected findings gate violation, got %+v fail=%v", violations, fail)
	}
}

func TestEvaluateIgnoresRules(t *testing.T) {
	target := Policy{FailOn: []string{"LOW"}, IgnoreRules: []string{"WeakTyping01"}}
	findings := []auditor.Finding{
		{RuleID: "WeakTyping01", Severity: auditor.SeverityLow},
	}
	if _, fail := Evaluate(target, findings); fail {
		t.Error("ignored rules must not trigger gates")
	}
}

func TestReport(t *testing.T) {
	if !strings.Contains(Report(nil), "no gate violations") {
		t.Error("expected clean report")
	}
	report := Report([]Violation{{Kind: "severity-gate", Detail: "boom"}})
	if !strings.Contains(report, "1 gate violations") || !strings.Contains(report, "boom") {
		t.Errorf("unexpected report: %s", report)
	}
}
