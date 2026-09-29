package schema

import (
	"testing"
)

func TestValidateTool(t *testing.T) {
	tests := []struct {
		name     string
		tool     Tool
		errCount int
	}{
		{
			name:     "valid tool",
			tool:     Tool{Name: "test", InputSchema: JSONSchema{Type: "object"}},
			errCount: 0,
		},
		{
			name:     "missing name",
			tool:     Tool{InputSchema: JSONSchema{Type: "object"}},
			errCount: 1,
		},
		{
			name:     "invalid root type",
			tool:     Tool{Name: "test", InputSchema: JSONSchema{Type: "invalid"}},
			errCount: 2,
		},
		{
			name: "path parameter without description",
			tool: Tool{
				Name: "test",
				InputSchema: JSONSchema{
					Type:       "object",
					Properties: map[string]JSONSchema{"filePath": {Type: "string"}},
				},
			},
			errCount: 1,
		},
		{
			name: "path parameter with description",
			tool: Tool{
				Name: "test",
				InputSchema: JSONSchema{
					Type: "object",
					Properties: map[string]JSONSchema{
						"filePath": {Type: "string", Description: "safe path"},
					},
				},
			},
			errCount: 0,
		},
		{
			name: "array with invalid item type",
			tool: Tool{
				Name: "test",
				InputSchema: JSONSchema{
					Type: "object",
					Properties: map[string]JSONSchema{
						"data": {Type: "array", Items: &JSONSchema{Type: "bogus"}},
					},
				},
			},
			errCount: 1,
		},
		{
			name: "nested object with invalid type",
			tool: Tool{
				Name: "test",
				InputSchema: JSONSchema{
					Type: "object",
					Properties: map[string]JSONSchema{
						"config": {Type: "object", Properties: map[string]JSONSchema{"inner": {Type: "bogus"}}},
					},
				},
			},
			errCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := ValidateTool(tc.tool)
			if len(errs) != tc.errCount {
				t.Errorf("expected %d errors, got %d: %+v", tc.errCount, len(errs), errs)
			}
		})
	}
}

func TestValidationErrorFormat(t *testing.T) {
	validationErr := ValidationError{Path: "inputSchema.type", Message: "invalid schema type"}
	want := "validation failed at inputSchema.type: invalid schema type"
	if validationErr.Error() != want {
		t.Errorf("expected %q, got %q", want, validationErr.Error())
	}
}
