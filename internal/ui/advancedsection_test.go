package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

func TestRenderReportAdvancedSection(t *testing.T) {
	findings := []auditor.Finding{
		{
			Severity:    auditor.SeverityHigh,
			RuleID:      "CmdInjection01",
			TargetTool:  "systemExec",
			Description: "static finding",
		},
		{
			Severity:    auditor.SeverityMedium,
			RuleID:      "StateDesync01",
			TargetTool:  "server",
			Description: "server accepted tools/list before initialize",
			Confirmed:   true,
			Evidence:    "lifecycle violation",
		},
		{
			Severity:    auditor.SeverityMedium,
			RuleID:      "RaceCondition01",
			TargetTool:  "tool",
			Description: "inconsistent concurrent outcomes",
		},
	}

	var buf bytes.Buffer
	renderReport(&buf, findings)

	out := buf.String()
	staticIdx := strings.Index(out, "CmdInjection01")
	sectionIdx := strings.Index(out, "--- Advanced Probes ---")
	desyncIdx := strings.Index(out, "StateDesync01")
	raceIdx := strings.Index(out, "RaceCondition01")
	if staticIdx == -1 || sectionIdx == -1 || desyncIdx == -1 || raceIdx == -1 {
		t.Fatal("expected static finding, advanced section and advanced findings in report")
	}
	if staticIdx > sectionIdx || sectionIdx > desyncIdx || desyncIdx > raceIdx {
		t.Error("expected advanced findings rendered after the separated section header")
	}
}
