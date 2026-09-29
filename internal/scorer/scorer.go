package scorer

import "github.com/kodivante/MCPwn/v3/internal/auditor"

type Grade string

const (
	GradeA Grade = "A"
	GradeB Grade = "B"
	GradeC Grade = "C"
	GradeD Grade = "D"
	GradeF Grade = "F"
)

type Score struct {
	Grade    Grade
	Critical int
	High     int
	Medium   int
	Low      int
	Total    int
}

func Calculate(findings []auditor.Finding) Score {
	s := Score{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case auditor.SeverityCritical:
			s.Critical++
		case auditor.SeverityHigh:
			s.High++
		case auditor.SeverityMedium:
			s.Medium++
		case auditor.SeverityLow:
			s.Low++
		}
	}
	s.Grade = gradeFromCounts(s)
	return s
}

func gradeFromCounts(s Score) Grade {
	switch {
	case s.Critical >= 3:
		return GradeF
	case s.Critical >= 1:
		return GradeD
	case s.High >= 3:
		return GradeC
	case s.High >= 1:
		return GradeB
	default:
		return GradeA
	}
}

func GradeColor(g Grade) string {
	switch g {
	case GradeA:
		return "#4c1"
	case GradeB:
		return "#97ca00"
	case GradeC:
		return "#dfb317"
	case GradeD:
		return "#fe7d37"
	default:
		return "#e05d44"
	}
}
