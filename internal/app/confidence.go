package app

import (
	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

const (
	confidenceConfirmed  = 95
	confidenceStatic     = 70
	confidenceBehavioral = 55
)

var advisoryRules = map[string]bool{
	"AdvisorHint01": true,
}

var behavioralRules = map[string]bool{
	"SideChannel01":   true,
	"SideChannel02":   true,
	"SideChannel03":   true,
	"MutationDiff01":  true,
	"Idempotency01":   true,
	"SequenceDrift01": true,
}

func applyConfidence(findings []auditor.Finding) {
	for i := range findings {
		setFindingConfidence(&findings[i])
	}
}

func setFindingConfidence(finding *auditor.Finding) {
	switch {
	case advisoryRules[finding.RuleID]:
		finding.SetConfidence(40)
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
