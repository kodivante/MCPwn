package auditor

import (
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/schema"
)

func TestTemplateInjectionRule(t *testing.T) {
	cases := []struct {
		name        string
		tool        schema.Tool
		wantFinding bool
	}{
		{
			name: "template param with render description",
			tool: schema.Tool{
				Name: "renderDoc",
				InputSchema: schema.JSONSchema{
					Type: "object",
					Properties: map[string]schema.JSONSchema{
						"template": {Type: "string", Description: "Jinja template to render"},
					},
				},
			},
			wantFinding: true,
		},
		{
			name: "template param without render context",
			tool: schema.Tool{
				Name: "storeDoc",
				InputSchema: schema.JSONSchema{
					Type: "object",
					Properties: map[string]schema.JSONSchema{
						"template": {Type: "string", Description: "name of the document"},
					},
				},
			},
			wantFinding: false,
		},
		{
			name: "non template param",
			tool: schema.Tool{
				Name: "greet",
				InputSchema: schema.JSONSchema{
					Type:       "object",
					Properties: map[string]schema.JSONSchema{"name": {Type: "string"}},
				},
			},
			wantFinding: false,
		},
	}
	rule := &TemplateInjectionRule{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := rule.Evaluate(tc.tool)
			if tc.wantFinding && len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}
			if tc.wantFinding && findings[0].RuleID != "TemplateInjection01" {
				t.Errorf("unexpected rule id %s", findings[0].RuleID)
			}
			if !tc.wantFinding && len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d", len(findings))
			}
		})
	}
}

func TestUnsafeDeserializationRule(t *testing.T) {
	rule := &UnsafeDeserializationRule{}
	vulnerable := schema.Tool{
		Name:        "loadState",
		Description: "Unpickle a previously saved state object",
		InputSchema: schema.JSONSchema{
			Type:       "object",
			Properties: map[string]schema.JSONSchema{"data": {Type: "string"}},
		},
	}
	findings := rule.Evaluate(vulnerable)
	if len(findings) != 1 || findings[0].RuleID != "UnsafeDeserialization01" {
		t.Fatalf("expected UnsafeDeserialization01, got %+v", findings)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
	clean := schema.Tool{
		Name: "addNumbers",
		InputSchema: schema.JSONSchema{
			Type:       "object",
			Properties: map[string]schema.JSONSchema{"a": {Type: "number"}},
		},
	}
	if findings := rule.Evaluate(clean); len(findings) != 0 {
		t.Errorf("expected 0 findings on clean tool, got %+v", findings)
	}
}

func TestPrototypePollutionRule(t *testing.T) {
	rule := &PrototypePollutionRule{}
	vulnerable := schema.Tool{
		Name: "mergeConfig",
		InputSchema: schema.JSONSchema{
			Type: "object",
			Properties: map[string]schema.JSONSchema{
				"options": {Type: "object", Description: "options to merge into the base configuration"},
			},
		},
	}
	findings := rule.Evaluate(vulnerable)
	if len(findings) != 1 || findings[0].RuleID != "PrototypePollution01" {
		t.Fatalf("expected PrototypePollution01, got %+v", findings)
	}
	clean := schema.Tool{
		Name: "getConfig",
		InputSchema: schema.JSONSchema{
			Type:       "object",
			Properties: map[string]schema.JSONSchema{"key": {Type: "string"}},
		},
	}
	if findings := rule.Evaluate(clean); len(findings) != 0 {
		t.Errorf("expected 0 findings on clean tool, got %+v", findings)
	}
}

func TestNoSqlInjectionRule(t *testing.T) {
	rule := &NoSqlInjectionRule{}
	vulnerable := schema.Tool{
		Name:        "findUser",
		Description: "Query the mongo collection for users",
		InputSchema: schema.JSONSchema{
			Type:       "object",
			Properties: map[string]schema.JSONSchema{"filter": {Type: "string"}},
		},
	}
	findings := rule.Evaluate(vulnerable)
	if len(findings) != 1 || findings[0].RuleID != "NoSqlInjection01" {
		t.Fatalf("expected NoSqlInjection01, got %+v", findings)
	}
	sqlTool := schema.Tool{
		Name: "runSql",
		InputSchema: schema.JSONSchema{
			Type:       "object",
			Properties: map[string]schema.JSONSchema{"query": {Type: "string", Description: "raw postgres query"}},
		},
	}
	if findings := rule.Evaluate(sqlTool); len(findings) != 0 {
		t.Errorf("expected 0 nosql findings on sql tool, got %+v", findings)
	}
}
