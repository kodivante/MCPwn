package auditor

import (
	"encoding/json"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/schema"
)

func toolWithProps(name string, props map[string]schema.JSONSchema) schema.Tool {
	return schema.Tool{
		Name:        name,
		InputSchema: schema.JSONSchema{Type: "object", Properties: props},
	}
}

func TestCommandInjectionRule(t *testing.T) {
	tests := []struct {
		name        string
		tool        schema.Tool
		wantFinding bool
	}{
		{
			name:        "raw command string",
			tool:        toolWithProps("testTool", map[string]schema.JSONSchema{"cmd": {Type: "string"}}),
			wantFinding: true,
		},
		{
			name: "command restricted by enum",
			tool: toolWithProps("testTool", map[string]schema.JSONSchema{
				"cmd": {Type: "string", Enum: []json.RawMessage{[]byte(`"ls"`)}},
			}),
		},
		{
			name: "numeric command",
			tool: toolWithProps("testTool", map[string]schema.JSONSchema{"cmd": {Type: "number"}}),
		},
		{
			name: "unrelated string",
			tool: toolWithProps("testTool", map[string]schema.JSONSchema{"color": {Type: "string"}}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := (&CommandInjectionRule{}).Evaluate(tc.tool)
			if tc.wantFinding && len(findings) != 1 {
				t.Errorf("expected 1 finding, got %d", len(findings))
			}
			if !tc.wantFinding && len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d", len(findings))
			}
		})
	}
}

func TestPathTraversalRule(t *testing.T) {
	tests := []struct {
		name        string
		tool        schema.Tool
		wantFinding bool
	}{
		{
			name:        "file path parameter",
			tool:        toolWithProps("testTool", map[string]schema.JSONSchema{"filePath": {Type: "string"}}),
			wantFinding: true,
		},
		{
			name:        "directory parameter",
			tool:        toolWithProps("testTool", map[string]schema.JSONSchema{"outputDir": {Type: "string"}}),
			wantFinding: true,
		},
		{
			name: "unrelated string",
			tool: toolWithProps("testTool", map[string]schema.JSONSchema{"content": {Type: "string"}}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := (&PathTraversalRule{}).Evaluate(tc.tool)
			if tc.wantFinding && len(findings) != 1 {
				t.Errorf("expected 1 finding, got %d", len(findings))
			}
			if !tc.wantFinding && len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d", len(findings))
			}
		})
	}
}

func TestSSRFRule(t *testing.T) {
	tests := []struct {
		name        string
		tool        schema.Tool
		wantFinding bool
	}{
		{
			name:        "webhook parameter",
			tool:        toolWithProps("testTool", map[string]schema.JSONSchema{"webhook": {Type: "string"}}),
			wantFinding: true,
		},
		{
			name:        "endpoint parameter",
			tool:        toolWithProps("testTool", map[string]schema.JSONSchema{"endpoint": {Type: "string"}}),
			wantFinding: true,
		},
		{
			name: "unrelated string",
			tool: toolWithProps("testTool", map[string]schema.JSONSchema{"title": {Type: "string"}}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := (&SSRFRule{}).Evaluate(tc.tool)
			if tc.wantFinding && len(findings) != 1 {
				t.Errorf("expected 1 finding, got %d", len(findings))
			}
			if !tc.wantFinding && len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d", len(findings))
			}
		})
	}
}

func TestCredentialsLeakRule(t *testing.T) {
	tests := []struct {
		name        string
		tool        schema.Tool
		wantFinding bool
	}{
		{
			name:        "password parameter",
			tool:        toolWithProps("testTool", map[string]schema.JSONSchema{"password": {Type: "string"}}),
			wantFinding: true,
		},
		{
			name:        "apikey parameter",
			tool:        toolWithProps("testTool", map[string]schema.JSONSchema{"apiKey": {Type: "string"}}),
			wantFinding: true,
		},
		{
			name: "username parameter",
			tool: toolWithProps("testTool", map[string]schema.JSONSchema{"username": {Type: "string"}}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := (&CredentialsLeakRule{}).Evaluate(tc.tool)
			if tc.wantFinding && len(findings) != 1 {
				t.Errorf("expected 1 finding, got %d", len(findings))
			}
			if !tc.wantFinding && len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d", len(findings))
			}
		})
	}
}

func TestSQLInjectionRule(t *testing.T) {
	tests := []struct {
		name        string
		tool        schema.Tool
		wantFinding bool
	}{
		{
			name:        "query parameter",
			tool:        toolWithProps("testTool", map[string]schema.JSONSchema{"query": {Type: "string"}}),
			wantFinding: true,
		},
		{
			name:        "sql parameter",
			tool:        toolWithProps("testTool", map[string]schema.JSONSchema{"sqlText": {Type: "string"}}),
			wantFinding: true,
		},
		{
			name: "unrelated string",
			tool: toolWithProps("testTool", map[string]schema.JSONSchema{"filter": {Type: "string"}}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := (&SQLInjectionRule{}).Evaluate(tc.tool)
			if tc.wantFinding && len(findings) != 1 {
				t.Errorf("expected 1 finding, got %d", len(findings))
			}
			if !tc.wantFinding && len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d", len(findings))
			}
		})
	}
}

func TestDosRule(t *testing.T) {
	tests := []struct {
		name        string
		tool        schema.Tool
		wantFinding bool
	}{
		{
			name:        "read file tool without limit",
			tool:        toolWithProps("read_file", map[string]schema.JSONSchema{"filePath": {Type: "string"}}),
			wantFinding: true,
		},
		{
			name: "read file tool with limit",
			tool: toolWithProps("read_file", map[string]schema.JSONSchema{
				"filePath": {Type: "string"},
				"maxLines": {Type: "number"},
			}),
		},
		{
			name: "read file tool with limit inside array items",
			tool: schema.Tool{
				Name: "read_file",
				InputSchema: schema.JSONSchema{
					Type: "object",
					Properties: map[string]schema.JSONSchema{
						"files": {
							Type: "array",
							Items: &schema.JSONSchema{
								Type:       "object",
								Properties: map[string]schema.JSONSchema{"maxLines": {Type: "number"}},
							},
						},
					},
				},
			},
		},
		{
			name: "unrelated tool",
			tool: toolWithProps("list_items", map[string]schema.JSONSchema{"pageNumber": {Type: "number"}}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := (&DosRule{}).Evaluate(tc.tool)
			if tc.wantFinding && len(findings) != 1 {
				t.Errorf("expected 1 finding, got %d", len(findings))
			}
			if !tc.wantFinding && len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d", len(findings))
			}
		})
	}
}

func TestStateMutationRule(t *testing.T) {
	tests := []struct {
		name        string
		tool        schema.Tool
		wantFinding bool
	}{
		{
			name:        "delete tool without confirmation",
			tool:        toolWithProps("delete_user", map[string]schema.JSONSchema{"userId": {Type: "string"}}),
			wantFinding: true,
		},
		{
			name: "delete tool with confirmation",
			tool: toolWithProps("delete_user", map[string]schema.JSONSchema{
				"userId":  {Type: "string"},
				"confirm": {Type: "boolean"},
			}),
		},
		{
			name: "read only tool",
			tool: toolWithProps("read_config", map[string]schema.JSONSchema{"key": {Type: "string"}}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := (&StateMutationRule{}).Evaluate(tc.tool)
			if tc.wantFinding && len(findings) != 1 {
				t.Errorf("expected 1 finding, got %d", len(findings))
			}
			if !tc.wantFinding && len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d", len(findings))
			}
		})
	}
}

func TestPromptInjectionRule(t *testing.T) {
	tests := []struct {
		name        string
		tool        schema.Tool
		wantFinding bool
	}{
		{
			name:        "prompt parameter",
			tool:        toolWithProps("chatTool", map[string]schema.JSONSchema{"prompt": {Type: "string"}}),
			wantFinding: true,
		},
		{
			name:        "instructions parameter",
			tool:        toolWithProps("chatTool", map[string]schema.JSONSchema{"instructions": {Type: "string"}}),
			wantFinding: true,
		},
		{
			name:        "message parameter",
			tool:        toolWithProps("chatTool", map[string]schema.JSONSchema{"userMessage": {Type: "string"}}),
			wantFinding: true,
		},
		{
			name: "unrelated string",
			tool: toolWithProps("chatTool", map[string]schema.JSONSchema{"filename": {Type: "string"}}),
		},
		{
			name: "numeric prompt",
			tool: toolWithProps("chatTool", map[string]schema.JSONSchema{"prompt": {Type: "number"}}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := (&PromptInjectionRule{}).Evaluate(tc.tool)
			if tc.wantFinding && len(findings) != 1 {
				t.Errorf("expected 1 finding, got %d", len(findings))
			}
			if !tc.wantFinding && len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d", len(findings))
			}
		})
	}
}

func TestNewEngineWithOptionsPromptInjection(t *testing.T) {
	tool := toolWithProps("chatTool", map[string]schema.JSONSchema{"prompt": {Type: "string"}})

	base := NewEngine()
	hasPromptBase := false
	for _, f := range base.AuditTools([]schema.Tool{tool}) {
		if f.RuleID == "PromptInjection01" {
			hasPromptBase = true
		}
	}
	if hasPromptBase {
		t.Errorf("expected PromptInjection01 to be disabled by default")
	}

	enabled := NewEngineWithOptions(EngineOptions{EnablePromptInjection: true})
	hasPromptEnabled := false
	for _, f := range enabled.AuditTools([]schema.Tool{tool}) {
		if f.RuleID == "PromptInjection01" {
			hasPromptEnabled = true
		}
	}
	if !hasPromptEnabled {
		t.Errorf("expected PromptInjection01 to be enabled with flag")
	}
}

func TestRuleSchemaRecursion(t *testing.T) {
	tool := schema.Tool{
		Name: "deepTool",
		InputSchema: schema.JSONSchema{
			Type: "object",
			Properties: map[string]schema.JSONSchema{
				"config": {
					Type: "object",
					Properties: map[string]schema.JSONSchema{
						"sqlQuery": {Type: "string"},
					},
				},
			},
		},
	}
	findings := (&SQLInjectionRule{}).Evaluate(tool)
	if len(findings) != 1 {
		t.Fatalf("expected 1 nested finding, got %d", len(findings))
	}
	if findings[0].ParamPath != "inputSchema.properties[config].properties[sqlQuery]" {
		t.Errorf("unexpected param path: %s", findings[0].ParamPath)
	}
}
