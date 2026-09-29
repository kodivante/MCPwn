package risk

import (
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

type Index struct {
	Index int    `json:"index"`
	Grade string `json:"grade"`
}

const (
	chainAmplification = 10
	densityStep        = 5
	densityCap         = 20
)

func FindingRisk(f auditor.Finding) int {
	base := severityBase(f.Severity)
	if base == 0 {
		return 0
	}
	factor := 0.7
	if f.Confirmed {
		factor = 1.0
	}
	confidence := f.Confidence
	if confidence == 0 {
		if f.Confirmed {
			confidence = 90
		} else {
			confidence = 70
		}
	}
	score := float64(base) * factor * (0.5 + 0.005*float64(confidence))
	if strings.HasPrefix(f.RuleID, "AttackChain") {
		score += chainAmplification
	}
	return clamp(score)
}

func ServerIndex(findings []auditor.Finding) Index {
	top := 0
	densityFindings := 0
	chainPresent := false
	for _, finding := range findings {
		score := FindingRisk(finding)
		if score > top {
			top = score
		}
		if finding.Severity == auditor.SeverityCritical || finding.Severity == auditor.SeverityHigh {
			densityFindings++
		}
		if strings.HasPrefix(finding.RuleID, "AttackChain") {
			chainPresent = true
		}
	}

	bonus := 0
	if densityFindings > 1 {
		bonus += min(densityCap, (densityFindings-1)*densityStep)
	}
	if chainPresent {
		bonus += chainAmplification
	}
	index := clampInt(top + bonus)
	return Index{Index: index, Grade: gradeFromIndex(index)}
}

func severityBase(severity auditor.Severity) int {
	switch severity {
	case auditor.SeverityCritical:
		return 100
	case auditor.SeverityHigh:
		return 75
	case auditor.SeverityMedium:
		return 50
	case auditor.SeverityLow:
		return 25
	default:
		return 0
	}
}

func gradeFromIndex(index int) string {
	switch {
	case index >= 85:
		return "F"
	case index >= 60:
		return "D"
	case index >= 40:
		return "C"
	case index >= 20:
		return "B"
	default:
		return "A"
	}
}

func clamp(score float64) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return int(score)
}

func clampInt(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
