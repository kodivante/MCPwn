package scorer

import (
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

func TestCalculate(t *testing.T) {
	tests := []struct {
		name      string
		findings  []auditor.Finding
		wantGrade Grade
		wantCrit  int
		wantHigh  int
	}{
		{
			name:      "no findings",
			wantGrade: GradeA,
		},
		{
			name:      "one high",
			findings:  []auditor.Finding{{Severity: auditor.SeverityHigh}},
			wantGrade: GradeB,
			wantHigh:  1,
		},
		{
			name: "three highs",
			findings: []auditor.Finding{
				{Severity: auditor.SeverityHigh},
				{Severity: auditor.SeverityHigh},
				{Severity: auditor.SeverityHigh},
			},
			wantGrade: GradeC,
			wantHigh:  3,
		},
		{
			name:      "one critical",
			findings:  []auditor.Finding{{Severity: auditor.SeverityCritical}},
			wantGrade: GradeD,
			wantCrit:  1,
		},
		{
			name: "three criticals",
			findings: []auditor.Finding{
				{Severity: auditor.SeverityCritical},
				{Severity: auditor.SeverityCritical},
				{Severity: auditor.SeverityCritical},
			},
			wantGrade: GradeF,
			wantCrit:  3,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := Calculate(tc.findings)
			if s.Grade != tc.wantGrade {
				t.Errorf("expected grade %s, got %s", tc.wantGrade, s.Grade)
			}
			if s.Critical != tc.wantCrit {
				t.Errorf("expected %d critical, got %d", tc.wantCrit, s.Critical)
			}
			if s.High != tc.wantHigh {
				t.Errorf("expected %d high, got %d", tc.wantHigh, s.High)
			}
			if s.Total != len(tc.findings) {
				t.Errorf("expected total %d, got %d", len(tc.findings), s.Total)
			}
		})
	}
}

func TestGradeColor(t *testing.T) {
	colors := map[Grade]string{
		GradeA: "#4c1",
		GradeB: "#97ca00",
		GradeC: "#dfb317",
		GradeD: "#fe7d37",
		GradeF: "#e05d44",
	}
	for grade, want := range colors {
		if got := GradeColor(grade); got != want {
			t.Errorf("GradeColor(%s) = %s, want %s", grade, got, want)
		}
	}
}
