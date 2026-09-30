package reporter

import (
	"encoding/json"
	"fmt"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/owasp"
	"github.com/kodivante/MCPwn/v3/internal/version"
)

type SARIFReport struct {
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name    string      `json:"name"`
	Rules   []SARIFRule `json:"rules"`
	Version string      `json:"version,omitempty"`
}

type SARIFRule struct {
	ID               string           `json:"id"`
	ShortDescription SARIFDescription `json:"shortDescription"`
}

type SARIFResult struct {
	RuleID     string           `json:"ruleId"`
	Message    SARIFDescription `json:"message"`
	Level      string           `json:"level"`
	Properties SARIFProperties  `json:"properties,omitempty"`
}

type SARIFProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type SARIFDescription struct {
	Text string `json:"text"`
}

func GenerateSARIF(findings []auditor.Finding) ([]byte, error) {
	rules, results := mapFindingsToSARIF(findings)

	report := SARIFReport{
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:    "MCPwn",
						Rules:   rules,
						Version: version.Version,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("sarif generation failed: %w", err)
	}
	return data, nil
}

func mapFindingsToSARIF(findings []auditor.Finding) ([]SARIFRule, []SARIFResult) {
	results := make([]SARIFResult, 0, len(findings))
	rules := make([]SARIFRule, 0, len(findings))
	seenRules := make(map[string]bool)

	for _, f := range findings {
		if !seenRules[f.RuleID] {
			rules = append(rules, SARIFRule{
				ID:               f.RuleID,
				ShortDescription: SARIFDescription{Text: string(f.Severity) + " risk"},
			})
			seenRules[f.RuleID] = true
		}

		level := "warning"
		if f.Severity == auditor.SeverityCritical || f.Severity == auditor.SeverityHigh {
			level = "error"
		} else if f.Severity == auditor.SeverityLow {
			level = "note"
		}

		message := fmt.Sprintf("[%s] %s: %s", f.TargetTool, f.ParamPath, f.Description)
		if f.Confirmed {
			message += fmt.Sprintf(" [CONFIRMED: %s]", f.Evidence)
		}

		result := SARIFResult{
			RuleID:  f.RuleID,
			Message: SARIFDescription{Text: message},
			Level:   level,
		}
		var tags []string
		if owaspID := owasp.MapRule(f.RuleID); owaspID != "" {
			tags = append(tags, owaspID)
		}
		if f.Verification != "" {
			tags = append(tags, "verification:"+f.Verification)
		}
		if len(tags) > 0 {
			result.Properties = SARIFProperties{Tags: tags}
		}
		results = append(results, result)
	}
	return rules, results
}
