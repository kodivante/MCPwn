package reporter

import (
	"strings"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/scorer"
)

func TestGenerateBadge(t *testing.T) {
	tests := []struct {
		name      string
		findings  []auditor.Finding
		wantGrade string
		wantColor string
	}{
		{
			name:      "grade A no findings",
			findings:  nil,
			wantGrade: "A",
			wantColor: "#4c1",
		},
		{
			name:      "grade B one high",
			findings:  []auditor.Finding{{Severity: auditor.SeverityHigh}},
			wantGrade: "B",
			wantColor: "#97ca00",
		},
		{
			name:      "grade D one critical",
			findings:  []auditor.Finding{{Severity: auditor.SeverityCritical}},
			wantGrade: "D",
			wantColor: "#fe7d37",
		},
		{
			name: "grade F three criticals",
			findings: []auditor.Finding{
				{Severity: auditor.SeverityCritical},
				{Severity: auditor.SeverityCritical},
				{Severity: auditor.SeverityCritical},
			},
			wantGrade: "F",
			wantColor: "#e05d44",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svg := string(GenerateBadge(scorer.Calculate(tc.findings)))
			if !strings.Contains(svg, "<svg") {
				t.Error("expected svg root element")
			}
			if !strings.Contains(svg, "MCPwn") {
				t.Error("expected MCPwn label in badge")
			}
			if !strings.Contains(svg, tc.wantGrade) {
				t.Errorf("expected grade %s in badge", tc.wantGrade)
			}
			if !strings.Contains(svg, tc.wantColor) {
				t.Errorf("expected color %s in badge, got: %s", tc.wantColor, svg)
			}
		})
	}
}
