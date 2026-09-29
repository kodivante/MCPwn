package reporter

import (
	"encoding/json"
	"fmt"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

func GenerateJSON(findings []auditor.Finding) ([]byte, error) {
	if findings == nil {
		findings = []auditor.Finding{}
	}
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("json generation failed: %w", err)
	}
	return data, nil
}
