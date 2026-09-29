package auditor

import (
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/schema"
)

func TestEngineAuditsAllTools(t *testing.T) {
	engine := NewEngine()
	tools := []schema.Tool{
		toolWithProps("execTool", map[string]schema.JSONSchema{"cmd": {Type: "string"}}),
		toolWithProps("loginTool", map[string]schema.JSONSchema{"password": {Type: "string"}}),
	}
	findings := engine.AuditTools(tools)
	if len(findings) < 2 {
		t.Fatalf("expected findings for both tools, got %d", len(findings))
	}
	for _, f := range findings {
		if f.TargetTool == "" || f.RuleID == "" || f.Severity == "" {
			t.Errorf("incomplete finding: %+v", f)
		}
	}
}

func TestEngineEmptyTools(t *testing.T) {
	if findings := NewEngine().AuditTools(nil); len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}
