package auditor

import (
	"fmt"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/schema"
)

var poisoningKeywords = []string{
	"ignore previous", "forget previous", "disregard previous",
	"override instructions", "you are now", "act as",
	"new role", "jailbreak", "system prompt",
	"previous instructions", "ignore the above",
	"[system]", "<system>", "[/inst]", "<|im_start|>",
	"ignore all", "new instructions", "disregard all",
	"do not follow", "bypass restrictions",
}

type ToolPoisoningRule struct{}

func (r *ToolPoisoningRule) Evaluate(tool schema.Tool) []Finding {
	lowDesc := strings.ToLower(tool.Description)
	lowName := strings.ToLower(tool.Name)
	for _, keyword := range poisoningKeywords {
		if strings.Contains(lowDesc, keyword) || strings.Contains(lowName, keyword) {
			return []Finding{
				{
					Severity:    SeverityCritical,
					RuleID:      "ToolPoisoning01",
					TargetTool:  tool.Name,
					ParamPath:   "description",
					Description: fmt.Sprintf("Tool metadata contains adversarial instruction (%q)", keyword),
					Remediation: "Remove adversarial instructions from tool name and description. Descriptions must be informational only.",
				},
			}
		}
	}
	return nil
}
