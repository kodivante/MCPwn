package reporter

import (
	"encoding/json"
	"fmt"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/owasp"
)

type jsonFinding struct {
	auditor.Finding
	OwaspMcp string `json:"OwaspMcp,omitempty"`
}

func GenerateJSON(findings []auditor.Finding) ([]byte, error) {
	items := make([]jsonFinding, 0, len(findings))
	for _, finding := range findings {
		items = append(items, jsonFinding{Finding: finding, OwaspMcp: owasp.MapRule(finding.RuleID)})
	}
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("json generation failed: %w", err)
	}
	return data, nil
}
