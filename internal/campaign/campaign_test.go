package campaign

import (
	"strings"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/capability"
)

func TestBuildHypothesesFromFindings(t *testing.T) {
	findings := []auditor.Finding{
		{RuleID: "CmdInjection01", TargetTool: "systemExec"},
		{RuleID: "Ssrf01", TargetTool: "fetchUrl"},
		{RuleID: "StateDesync01", TargetTool: "server", Confirmed: true},
	}
	hypotheses := BuildHypotheses(findings, nil)
	byKey := map[string]bool{}
	for _, hypothesis := range hypotheses {
		byKey[hypothesis.RuleID+"|"+hypothesis.TargetTool] = true
	}
	if !byKey["CmdInjection01|systemExec"] {
		t.Error("expected cmd injection hypothesis")
	}
	if !byKey["Ssrf01|fetchUrl"] {
		t.Error("expected ssrf hypothesis")
	}
	if byKey["StateDesync01|server"] {
		t.Error("confirmed findings must not generate hypotheses")
	}
	found := false
	for _, hypothesis := range hypotheses {
		if hypothesis.RuleID == "ToolRugPull01" {
			found = true
		}
	}
	if !found {
		t.Error("expected server-level hypotheses")
	}
}

func TestBuildHypothesesFromCapabilities(t *testing.T) {
	profiles := []capability.ToolCapability{
		{Tool: "loginUser", Capabilities: []string{capability.Credentials}},
		{Tool: "runQuery", Capabilities: []string{capability.Database}},
	}
	hypotheses := BuildHypotheses(nil, profiles)
	found := false
	for _, hypothesis := range hypotheses {
		if hypothesis.TargetTool == "loginUser" && hypothesis.Probe == "token leak scan" {
			found = true
		}
		if hypothesis.TargetTool == "runQuery" && hypothesis.RuleID == capability.Database {
			t.Error("database capability has no probe mapping")
		}
	}
	if !found {
		t.Error("expected credentials capability hypothesis")
	}
}

func TestEvaluateMarksConfirmed(t *testing.T) {
	hypotheses := []Hypothesis{
		{RuleID: "CmdInjection01", TargetTool: "systemExec", Probe: "fuzzer", Status: StatusUnproven},
		{RuleID: "Ssrf01", TargetTool: "fetchUrl", Probe: "ssrf canary", Status: StatusUnproven},
	}
	findings := []auditor.Finding{
		{RuleID: "CmdInjection01", TargetTool: "systemExec", Confirmed: true},
	}
	evaluated := Evaluate(hypotheses, findings)
	if evaluated[0].Status != StatusConfirmed {
		t.Errorf("expected confirmed, got %s", evaluated[0].Status)
	}
	if evaluated[1].Status != StatusUnproven {
		t.Errorf("expected unproven, got %s", evaluated[1].Status)
	}
}

func TestEvaluateServerHypothesisConfirmed(t *testing.T) {
	hypotheses := []Hypothesis{{RuleID: "StateDesync01", Probe: "lifecycle desync probes", Status: StatusUnproven}}
	findings := []auditor.Finding{{RuleID: "StateDesync01", TargetTool: "server", Confirmed: true}}
	evaluated := Evaluate(hypotheses, findings)
	if evaluated[0].Status != StatusConfirmed {
		t.Errorf("expected server hypothesis confirmed, got %s", evaluated[0].Status)
	}
}

func TestReportRendersSummary(t *testing.T) {
	report := Report([]Hypothesis{
		{RuleID: "CmdInjection01", TargetTool: "systemExec", Probe: "fuzzer", Status: StatusConfirmed},
		{RuleID: "Ssrf01", TargetTool: "fetchUrl", Probe: "ssrf canary", Status: StatusUnproven},
	})
	if !strings.Contains(report, "2 hypotheses") || !strings.Contains(report, "1 confirmed") {
		t.Errorf("unexpected report: %s", report)
	}
	if !strings.Contains(report, "systemExec") || !strings.Contains(report, "[!]") {
		t.Errorf("expected formatted lines: %s", report)
	}
	if !strings.Contains(Report(nil), "no hypotheses") {
		t.Error("expected empty campaign report")
	}
}

func TestHypothesesDeduplicated(t *testing.T) {
	findings := []auditor.Finding{
		{RuleID: "CmdInjection01", TargetTool: "sameTool"},
		{RuleID: "CmdInjection01", TargetTool: "sameTool"},
	}
	hypotheses := BuildHypotheses(findings, nil)
	count := 0
	for _, hypothesis := range hypotheses {
		if hypothesis.RuleID == "CmdInjection01" && hypothesis.TargetTool == "sameTool" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected deduplicated hypotheses, got %d", count)
	}
}
