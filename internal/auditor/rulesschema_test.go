package auditor

import (
	"encoding/json"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/schema"
)

func boolPtr(b bool) *bool { return &b }

func TestIdorRule(t *testing.T) {
	tests := []struct {
		name     string
		tool     schema.Tool
		wantRule string
	}{
		{
			name: "userId without enum",
			tool: schema.Tool{Name: "get", InputSchema: schema.JSONSchema{
				Type: "object",
				Properties: map[string]schema.JSONSchema{
					"userId": {Type: "string"},
				},
			}},
			wantRule: "Idor01",
		},
		{
			name: "userId with enum",
			tool: schema.Tool{Name: "get", InputSchema: schema.JSONSchema{
				Type: "object",
				Properties: map[string]schema.JSONSchema{
					"userId": {Type: "string", Enum: []json.RawMessage{[]byte(`"a"`), []byte(`"b"`)}},
				},
			}},
		},
		{
			name: "non-idor param",
			tool: schema.Tool{Name: "exec", InputSchema: schema.JSONSchema{
				Type:       "object",
				Properties: map[string]schema.JSONSchema{"cmd": {Type: "string"}},
			}},
		},
	}
	rule := &IdorRule{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := rule.Evaluate(tc.tool)
			if tc.wantRule == "" {
				if len(findings) != 0 {
					t.Errorf("expected no findings, got %d", len(findings))
				}
				return
			}
			if len(findings) == 0 {
				t.Fatalf("expected finding %s, got none", tc.wantRule)
			}
			if findings[0].RuleID != tc.wantRule {
				t.Errorf("expected %s, got %s", tc.wantRule, findings[0].RuleID)
			}
		})
	}
}

func TestMassAssignmentRule(t *testing.T) {
	tests := []struct {
		name     string
		tool     schema.Tool
		wantRule string
	}{
		{
			name: "object without additionalProperties",
			tool: schema.Tool{Name: "create", InputSchema: schema.JSONSchema{
				Type:       "object",
				Properties: map[string]schema.JSONSchema{"name": {Type: "string"}},
			}},
			wantRule: "MassAssignment01",
		},
		{
			name: "object with additionalProperties false",
			tool: schema.Tool{Name: "create", InputSchema: schema.JSONSchema{
				Type:                 "object",
				Properties:           map[string]schema.JSONSchema{"name": {Type: "string"}},
				AdditionalProperties: boolPtr(false),
			}},
		},
		{
			name: "non-object schema",
			tool: schema.Tool{Name: "echo", InputSchema: schema.JSONSchema{
				Type:                 "object",
				Properties:           map[string]schema.JSONSchema{"msg": {Type: "string"}},
				AdditionalProperties: boolPtr(false),
			}},
		},
	}
	rule := &MassAssignmentRule{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := rule.Evaluate(tc.tool)
			if tc.wantRule == "" {
				if len(findings) != 0 {
					t.Errorf("expected no findings, got %d", len(findings))
				}
				return
			}
			if len(findings) == 0 {
				t.Fatalf("expected %s, got none", tc.wantRule)
			}
			if findings[0].RuleID != tc.wantRule {
				t.Errorf("expected %s, got %s", tc.wantRule, findings[0].RuleID)
			}
		})
	}
}

func TestWeakTypingRule(t *testing.T) {
	tests := []struct {
		name     string
		tool     schema.Tool
		wantRule string
	}{
		{
			name: "typed param",
			tool: schema.Tool{Name: "t", InputSchema: schema.JSONSchema{
				Type:       "object",
				Properties: map[string]schema.JSONSchema{"cmd": {Type: "string"}},
			}},
		},
		{
			name: "untyped param",
			tool: schema.Tool{Name: "t", InputSchema: schema.JSONSchema{
				Type:       "object",
				Properties: map[string]schema.JSONSchema{"data": {}},
			}},
			wantRule: "WeakTyping01",
		},
	}
	rule := &WeakTypingRule{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := rule.Evaluate(tc.tool)
			if tc.wantRule == "" {
				if len(findings) != 0 {
					t.Errorf("expected no findings, got %d", len(findings))
				}
				return
			}
			if len(findings) == 0 {
				t.Fatalf("expected %s, got none", tc.wantRule)
			}
			if findings[0].RuleID != tc.wantRule {
				t.Errorf("expected %s, got %s", tc.wantRule, findings[0].RuleID)
			}
		})
	}
}

func TestMissingRequiredRule(t *testing.T) {
	tests := []struct {
		name     string
		tool     schema.Tool
		wantRule string
	}{
		{
			name: "id in required",
			tool: schema.Tool{Name: "get", InputSchema: schema.JSONSchema{
				Type:       "object",
				Properties: map[string]schema.JSONSchema{"id": {Type: "string"}},
				Required:   []string{"id"},
			}},
		},
		{
			name: "id not in required",
			tool: schema.Tool{Name: "get", InputSchema: schema.JSONSchema{
				Type:       "object",
				Properties: map[string]schema.JSONSchema{"id": {Type: "string"}},
			}},
			wantRule: "MissingRequired01",
		},
		{
			name: "non-critical param not in required",
			tool: schema.Tool{Name: "list", InputSchema: schema.JSONSchema{
				Type:       "object",
				Properties: map[string]schema.JSONSchema{"pageNumber": {Type: "number"}},
			}},
		},
	}
	rule := &MissingRequiredRule{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := rule.Evaluate(tc.tool)
			if tc.wantRule == "" {
				if len(findings) != 0 {
					t.Errorf("expected no findings, got %d", len(findings))
				}
				return
			}
			if len(findings) == 0 {
				t.Fatalf("expected %s, got none", tc.wantRule)
			}
			if findings[0].RuleID != tc.wantRule {
				t.Errorf("expected %s, got %s", tc.wantRule, findings[0].RuleID)
			}
		})
	}
}
