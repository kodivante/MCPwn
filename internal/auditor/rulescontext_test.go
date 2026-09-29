package auditor

import (
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/schema"
)

func TestContextSharingRule(t *testing.T) {
	cases := []struct {
		name        string
		tool        schema.Tool
		wantFinding bool
		wantMarker  string
	}{
		{
			name:        "env file in description",
			tool:        schema.Tool{Name: "readConfig", Description: "Reads the .env file from the project root"},
			wantFinding: true,
			wantMarker:  ".env",
		},
		{
			name:        "private key reference",
			tool:        schema.Tool{Name: "deploy", Description: "Deploys using the private key stored on disk"},
			wantFinding: true,
			wantMarker:  "private key",
		},
		{
			name:        "ssh config marker",
			tool:        schema.Tool{Name: "ssh", Description: "Manages the ssh config of the host"},
			wantFinding: true,
			wantMarker:  "ssh config",
		},
		{
			name:        "marker in tool name",
			tool:        schema.Tool{Name: "id_rsa_loader", Description: "Loads identity"},
			wantFinding: true,
			wantMarker:  "id_rsa",
		},
		{
			name:        "clean description",
			tool:        schema.Tool{Name: "listFiles", Description: "Lists files inside the workspace"},
			wantFinding: false,
		},
		{
			name:        "empty description",
			tool:        schema.Tool{Name: "ping"},
			wantFinding: false,
		},
	}
	rule := &ContextSharingRule{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := rule.Evaluate(tc.tool)
			if tc.wantFinding {
				if len(findings) != 1 {
					t.Fatalf("expected 1 finding, got %d", len(findings))
				}
				if findings[0].RuleID != "ContextSharing01" {
					t.Errorf("unexpected rule id %s", findings[0].RuleID)
				}
				if findings[0].Severity != SeverityMedium {
					t.Errorf("expected MEDIUM severity, got %s", findings[0].Severity)
				}
				if findings[0].TargetTool != tc.tool.Name {
					t.Errorf("expected target tool %s, got %s", tc.tool.Name, findings[0].TargetTool)
				}
			} else if len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d: %+v", len(findings), findings)
			}
		})
	}
}

func TestContextSharingRuleRegistered(t *testing.T) {
	engine := NewEngine()
	for _, rule := range engine.rules {
		if _, ok := rule.(*ContextSharingRule); ok {
			return
		}
	}
	t.Error("expected ContextSharingRule registered in default engine")
}
