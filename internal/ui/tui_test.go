package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

func TestRenderReportEmpty(t *testing.T) {
	var buf bytes.Buffer
	renderReport(&buf, nil)
	if !strings.Contains(buf.String(), "No vulnerabilities found.") {
		t.Error("expected empty report message")
	}
}

func TestRenderReportPromptInjectSection(t *testing.T) {
	findings := []auditor.Finding{
		{
			Severity:    auditor.SeverityCritical,
			RuleID:      "CmdInjection01",
			TargetTool:  "systemExec",
			Description: "raw command execution",
		},
		{
			Severity:    auditor.SeverityHigh,
			RuleID:      "PromptInjectionReflection",
			TargetTool:  "chatTool",
			Description: "reflects user input verbatim",
			Confirmed:   true,
			Evidence:    "probe returned unescaped",
		},
	}

	var buf bytes.Buffer
	renderReport(&buf, findings)

	out := buf.String()
	staticIdx := strings.Index(out, "CmdInjection01")
	sectionIdx := strings.Index(out, "--- Prompt Injection Simulation ---")
	injectedIdx := strings.Index(out, "PromptInjectionReflection")
	if staticIdx == -1 || sectionIdx == -1 || injectedIdx == -1 {
		t.Fatal("expected static finding, section header and injected finding in report")
	}
	if staticIdx > sectionIdx || sectionIdx > injectedIdx {
		t.Error("expected injected findings rendered after the separated section header")
	}
}

func TestRenderReportFindings(t *testing.T) {
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
			Severity:    auditor.SeverityLow,
			RuleID:      "SchemaValidation01",
			TargetTool:  "reader",
			ParamPath:   "inputSchema",
			Description: "path parameter lacks description",
		},
	}

	var buf bytes.Buffer
	renderReport(&buf, findings)

	out := buf.String()
	for _, want := range []string{
		"MCPwn Audit Report v",
		"[!]",
		"CRITICAL",
		"systemExec",
		"CmdInjection01",
		"Evidence:",
		"[?]",
		"LOW",
		"reader",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %s in report", want)
		}
	}
}
