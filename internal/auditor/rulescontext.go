package auditor

import (
	"fmt"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/schema"
)

type ContextSharingRule struct{}

var contextSharingMarkers = []string{
	".env",
	"id_rsa",
	"private key",
	"credentials file",
	"secrets file",
	"ssh config",
	"keystore",
	"wallet file",
}

func (r *ContextSharingRule) Evaluate(tool schema.Tool) []Finding {
	text := strings.ToLower(tool.Name + " " + tool.Description)
	for _, marker := range contextSharingMarkers {
		if !strings.Contains(text, marker) {
			continue
		}
		return []Finding{
			{
				Severity:    SeverityMedium,
				RuleID:      "ContextSharing01",
				TargetTool:  tool.Name,
				ParamPath:   "description",
				Description: fmt.Sprintf("Tool metadata exposes sensitive context marker '%s', encouraging over-sharing of secrets with the agent", marker),
				Remediation: "Remove secret file references and credential markers from tool metadata; scope tools to the minimum context they require.",
			},
		}
	}
	return nil
}
