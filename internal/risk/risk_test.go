package risk

import (
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

func TestFindingRisk(t *testing.T) {
	cases := []struct {
		name    string
		finding auditor.Finding
		minRisk int
		maxRisk int
	}{
		{
			name:    "confirmed critical with evidence",
			finding: auditor.Finding{Severity: auditor.SeverityCritical, Confirmed: true, Evidence: "x", Confidence: 95},
			minRisk: 95,
			maxRisk: 100,
		},
		{
			name:    "static critical is a hypothesis",
			finding: auditor.Finding{Severity: auditor.SeverityCritical, Confidence: 70},
			minRisk: 45,
			maxRisk: 65,
		},
		{
			name:    "static low stays low",
			finding: auditor.Finding{Severity: auditor.SeverityLow, Confidence: 70},
			minRisk: 0,
			maxRisk: 25,
		},
		{
			name:    "attack chain amplified",
			finding: auditor.Finding{Severity: auditor.SeverityHigh, RuleID: "AttackChain01", Confidence: 70},
			minRisk: 50,
			maxRisk: 80,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			score := FindingRisk(tc.finding)
			if score < tc.minRisk || score > tc.maxRisk {
				t.Errorf("expected risk between %d and %d, got %d", tc.minRisk, tc.maxRisk, score)
			}
		})
	}
}

func TestServerIndexGrades(t *testing.T) {
	cases := []struct {
		name     string
		goal     string
		findings []auditor.Finding
	}{
		{
			name: "clean server is grade A",
			goal: "A",
		},
		{
			name:     "single static medium stays in low bands",
			goal:     "B",
			findings: []auditor.Finding{{Severity: auditor.SeverityMedium, Confidence: 70}},
		},
		{
			name:     "confirmed critical is grade F",
			goal:     "F",
			findings: []auditor.Finding{{Severity: auditor.SeverityCritical, Confirmed: true, Evidence: "x", Confidence: 95}},
		},
		{
			name: "many confirmed highs reach D with density bonus",
			goal: "D",
			findings: []auditor.Finding{
				{Severity: auditor.SeverityHigh, Confirmed: true, Evidence: "x", Confidence: 95},
				{Severity: auditor.SeverityHigh, Confirmed: true, Evidence: "y", Confidence: 95},
				{Severity: auditor.SeverityHigh, Confirmed: true, Evidence: "z", Confidence: 95},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			index := ServerIndex(tc.findings)
			if index.Grade != tc.goal {
				t.Errorf("expected grade %s, got %s (index %d)", tc.goal, index.Grade, index.Index)
			}
			if index.Index < 0 || index.Index > 100 {
				t.Errorf("index out of range: %d", index.Index)
			}
		})
	}
}

func TestServerIndexChainBonus(t *testing.T) {
	base := []auditor.Finding{{Severity: auditor.SeverityHigh, Confirmed: true, Evidence: "x", Confidence: 95}}
	withoutChain := ServerIndex(base)
	withChain := ServerIndex(append(append([]auditor.Finding{}, base...),
		auditor.Finding{Severity: auditor.SeverityHigh, RuleID: "AttackChain02", Confidence: 70}))
	if withChain.Index <= withoutChain.Index {
		t.Errorf("expected chain to amplify index: %d vs %d", withChain.Index, withoutChain.Index)
	}
}

func TestFindingRiskZeroSeverity(t *testing.T) {
	if score := FindingRisk(auditor.Finding{}); score != 0 {
		t.Errorf("expected 0 risk for unknown severity, got %d", score)
	}
}
