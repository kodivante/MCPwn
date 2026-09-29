package schema

import (
	"testing"
)

func TestParseTool(t *testing.T) {
	data := []byte(`{
		"name": "execute",
		"description": "Executes a command",
		"inputSchema": {
			"type": "object",
			"properties": {
				"command": {
					"type": "string"
				}
			},
			"required": ["command"]
		}
	}`)

	tool, err := ParseTool(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tool.Name != "execute" {
		t.Errorf("expected name execute, got %s", tool.Name)
	}

	if tool.InputSchema.Type != "object" {
		t.Errorf("expected type object, got %s", tool.InputSchema.Type)
	}

	prop, ok := tool.InputSchema.Properties["command"]
	if !ok {
		t.Fatalf("expected command property")
	}
	if prop.Type != "string" {
		t.Errorf("expected command type string, got %s", prop.Type)
	}
}

func TestParseToolInvalidJSON(t *testing.T) {
	if _, err := ParseTool([]byte(`{invalid`)); err == nil {
		t.Error("expected parse error")
	}
}

func TestParseToolFullSchema(t *testing.T) {
	data := []byte(`{
		"name": "run",
		"description": "Runs a job",
		"inputSchema": {
			"type": "object",
			"properties": {
				"mode": {"type": "string", "enum": ["fast", "slow"]},
				"tags": {"type": "array", "items": {"type": "string"}},
				"force": {"type": "boolean"}
			},
			"required": ["mode"],
			"additionalProperties": false
		}
	}`)

	tool, err := ParseTool(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tool.Description != "Runs a job" {
		t.Errorf("unexpected description: %s", tool.Description)
	}

	mode, ok := tool.InputSchema.Properties["mode"]
	if !ok {
		t.Fatal("expected mode property")
	}
	if len(mode.Enum) != 2 {
		t.Errorf("expected 2 enum values, got %d", len(mode.Enum))
	}

	tags, ok := tool.InputSchema.Properties["tags"]
	if !ok {
		t.Fatal("expected tags property")
	}
	if tags.Items == nil || tags.Items.Type != "string" {
		t.Error("expected tags items type string")
	}

	if tool.InputSchema.AdditionalProperties == nil || *tool.InputSchema.AdditionalProperties {
		t.Error("expected additionalProperties false")
	}

	if len(tool.InputSchema.Required) != 1 || tool.InputSchema.Required[0] != "mode" {
		t.Errorf("unexpected required fields: %v", tool.InputSchema.Required)
	}
}
