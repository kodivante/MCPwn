package reporter

import (
	"html"
	"strings"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/version"
)

func TestGenerateHTMLEmpty(t *testing.T) {
	data, err := GenerateHTML(nil)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if !strings.Contains(out, "No vulnerabilities found.") {
		t.Error("expected empty state message")
	}
	if !strings.Contains(out, "<title>MCPwn Audit Report v"+version.Version+"</title>") {
		t.Error("expected report title with version")
	}
}

func TestGenerateHTMLFindings(t *testing.T) {
	findings := []auditor.Finding{
		{
			Severity:    auditor.SeverityCritical,
			RuleID:      "CmdInjection01",
			TargetTool:  "systemExec",
			ParamPath:   "inputSchema.properties[cmd]",
			Description: "raw command execution",
			Remediation: "use enum restrictions",
			Confirmed:   true,
			Evidence:    "marker mcpwn_probe found in tool response",
		},
		{
			Severity:    auditor.SeverityHigh,
			RuleID:      "PathTraversal01",
			TargetTool:  "reader",
			ParamPath:   "inputSchema.properties[filePath]",
			Description: "path traversal risk",
		},
	}
	data, err := GenerateHTML(findings)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	for _, want := range []string{
		"systemExec",
		"CmdInjection01",
		"[!] CONFIRMED",
		"Evidence: marker mcpwn_probe found in tool response",
		"reader",
		"PathTraversal01",
		"[?] DETECTED",
		`class="card critical"`,
		"CRITICAL · 1",
		"HIGH · 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in html report", want)
		}
	}
}

func TestGenerateHTMLSectionOrder(t *testing.T) {
	findings := []auditor.Finding{
		{Severity: auditor.SeverityLow, RuleID: "Low01", TargetTool: "lowTool", Description: "low risk"},
		{Severity: auditor.SeverityCritical, RuleID: "Crit01", TargetTool: "critTool", Description: "critical risk"},
		{Severity: auditor.SeverityMedium, RuleID: "Med01", TargetTool: "medTool", Description: "medium risk"},
		{Severity: auditor.SeverityHigh, RuleID: "High01", TargetTool: "highTool", Description: "high risk"},
	}
	data, err := GenerateHTML(findings)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	critical := strings.Index(out, "CRITICAL ·")
	high := strings.Index(out, "HIGH ·")
	medium := strings.Index(out, "MEDIUM ·")
	low := strings.Index(out, "LOW ·")
	if critical == -1 || high == -1 || medium == -1 || low == -1 {
		t.Fatal("expected all four severity sections in report")
	}
	if critical > high || high > medium || medium > low {
		t.Errorf("expected severity ordering critical<high<medium<low, got %d %d %d %d", critical, high, medium, low)
	}
}

func TestGenerateHTMLEscaping(t *testing.T) {
	findings := []auditor.Finding{
		{
			Severity:    auditor.SeverityHigh,
			RuleID:      "Escape01",
			TargetTool:  "<script>alert(1)</script>",
			Description: "untrusted <b>content</b>",
		},
	}
	data, err := GenerateHTML(findings)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if strings.Contains(out, "<script>alert") {
		t.Error("expected html escaping of tool names")
	}
	if !strings.Contains(out, html.EscapeString("<script>")) {
		t.Error("expected escaped tool name in report")
	}
	if !strings.Contains(out, html.EscapeString("<b>content</b>")) {
		t.Error("expected escaped description in report")
	}
}
