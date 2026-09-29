package reporter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/version"
)

func TestGenerateJSON(t *testing.T) {
	findings := []auditor.Finding{{Severity: auditor.SeverityCritical, RuleID: "Test01"}}
	data, err := GenerateJSON(findings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "CRITICAL") {
		t.Error("expected CRITICAL in output")
	}
}

func TestGenerateJSONEmpty(t *testing.T) {
	data, err := GenerateJSON(nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "[]" {
		t.Errorf("expected empty array, got %s", data)
	}
}

func TestGenerateJSONConfirmed(t *testing.T) {
	findings := []auditor.Finding{{
		Severity:  auditor.SeverityCritical,
		RuleID:    "Test01",
		Confirmed: true,
		Evidence:  "marker mcpwn_probe found in tool response",
	}}
	data, err := GenerateJSON(findings)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if !strings.Contains(out, `"Confirmed": true`) {
		t.Errorf("expected confirmed flag in json, got %s", out)
	}
	if !strings.Contains(out, "mcpwn_probe") {
		t.Errorf("expected evidence in json, got %s", out)
	}
}

func TestGenerateSARIFLevels(t *testing.T) {
	tests := []struct {
		name     string
		severity auditor.Severity
		want     string
	}{
		{name: "critical", severity: auditor.SeverityCritical, want: "error"},
		{name: "high", severity: auditor.SeverityHigh, want: "error"},
		{name: "medium", severity: auditor.SeverityMedium, want: "warning"},
		{name: "low", severity: auditor.SeverityLow, want: "note"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := GenerateSARIF([]auditor.Finding{{Severity: tc.severity, RuleID: "Test01"}})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `"level": "`+tc.want+`"`) {
				t.Errorf("expected level %s in SARIF output", tc.want)
			}
		})
	}
}

func TestGenerateSARIFRuleDedup(t *testing.T) {
	findings := []auditor.Finding{
		{Severity: auditor.SeverityHigh, RuleID: "Shared01"},
		{Severity: auditor.SeverityHigh, RuleID: "Shared01"},
	}
	data, err := GenerateSARIF(findings)
	if err != nil {
		t.Fatal(err)
	}
	var report SARIFReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unexpected sarif parsing error: %v", err)
	}
	if len(report.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("expected 1 deduped rule, got %d", len(report.Runs[0].Tool.Driver.Rules))
	}
	if len(report.Runs[0].Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(report.Runs[0].Results))
	}
}

func TestGenerateSARIFEmpty(t *testing.T) {
	data, err := GenerateSARIF(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"results": []`) {
		t.Errorf("expected empty results array, got %s", data)
	}
}

func TestGenerateSARIFConfirmed(t *testing.T) {
	findings := []auditor.Finding{{
		Severity:  auditor.SeverityCritical,
		RuleID:    "Test01",
		Confirmed: true,
		Evidence:  "marker mcpwn_probe found in tool response",
	}}
	data, err := GenerateSARIF(findings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "CONFIRMED") {
		t.Errorf("expected confirmed annotation in sarif, got %s", data)
	}
}

func TestGenerateSARIFDriverVersion(t *testing.T) {
	data, err := GenerateSARIF(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"version": "`+version.Version+`"`) {
		t.Errorf("expected driver version %s in sarif, got %s", version.Version, data)
	}
}
