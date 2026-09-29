package app

import (
	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

const (
	confidenceConfirmed  = 95
	confidenceStatic     = 70
	confidenceBehavioral = 55
)

var behavioralRules = map[string]bool{
	"SideChannel01": true,
	"SideChannel02": true,
	"SideChannel03": true,
}

func applyConfidence(findings []auditor.Finding) {
	for i := range findings {
		setFindingConfidence(&findings[i])
	}
}

func setFindingConfidence(finding *auditor.Finding) {
	switch {
	case behavioralRules[finding.RuleID]:
		finding.SetConfidence(confidenceBehavioral)
	case finding.Confirmed && finding.Evidence != "":
		finding.SetConfidence(confidenceConfirmed)
	case finding.Confirmed:
		finding.SetConfidence(confidenceConfirmed - 5)
	default:
		finding.SetConfidence(confidenceStatic)
	}
}
