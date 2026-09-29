package capability

import (
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/schema"
)

func TestProfile(t *testing.T) {
	tools := []schema.Tool{
		{
			Name:        "runCommand",
			Description: "Execute an OS command on the host",
			InputSchema: schema.JSONSchema{
				Type:       "object",
				Properties: map[string]schema.JSONSchema{"cmd": {Type: "string"}},
			},
		},
		{
			Name: "fetchUrl",
			InputSchema: schema.JSONSchema{
				Type:       "object",
				Properties: map[string]schema.JSONSchema{"url": {Type: "string"}},
			},
		},
		{
			Name: "loginUser",
			InputSchema: schema.JSONSchema{
				Type: "object",
				Properties: map[string]schema.JSONSchema{
					"password": {Type: "string"},
					"user":     {Type: "string"},
				},
			},
		},
	}
	profiles := Profile(tools)

	if !Contains(profiles[0], Exec) {
		t.Errorf("expected exec capability for runCommand, got %+v", profiles[0])
	}
	if !Contains(profiles[1], Network) {
		t.Errorf("expected network capability for fetchUrl, got %+v", profiles[1])
	}
	if !Contains(profiles[2], Credentials) {
		t.Errorf("expected credentials capability for loginUser, got %+v", profiles[2])
	}
	if Contains(profiles[2], Exec) {
		t.Errorf("unexpected exec capability for loginUser")
	}
}

func TestProfileReadsParamDescriptions(t *testing.T) {
	tool := schema.Tool{
		Name: "generic",
		InputSchema: schema.JSONSchema{
			Type: "object",
			Properties: map[string]schema.JSONSchema{
				"input": {Type: "string", Description: "sql statement to execute"},
			},
		},
	}
	profiles := Profile([]schema.Tool{tool})
	if !Contains(profiles[0], Database) {
		t.Errorf("expected database capability from param description, got %+v", profiles[0])
	}
}

func TestServerCapabilities(t *testing.T) {
	profiles := []ToolCapability{
		{Tool: "a", Capabilities: []string{Exec, Network}},
		{Tool: "b", Capabilities: []string{Network, Database}},
	}
	server := ServerCapabilities(profiles)
	if len(server) != 3 || server[0] != Database || server[1] != Exec || server[2] != Network {
		t.Errorf("unexpected server capabilities: %+v", server)
	}
}

func TestToolWithCapability(t *testing.T) {
	profiles := []ToolCapability{
		{Tool: "a", Capabilities: []string{Exec}},
		{Tool: "b", Capabilities: []string{Network}},
	}
	if tool, ok := ToolWithCapability(profiles, Network); !ok || tool != "b" {
		t.Errorf("expected b for network capability, got %s ok=%v", tool, ok)
	}
	if _, ok := ToolWithCapability(profiles, Credentials); ok {
		t.Error("expected no tool with credentials capability")
	}
}

func TestProfileCleanTool(t *testing.T) {
	tool := schema.Tool{Name: "calculator", InputSchema: schema.JSONSchema{Type: "object"}}
	profiles := Profile([]schema.Tool{tool})
	if len(profiles[0].Capabilities) != 0 {
		t.Errorf("expected no capabilities, got %+v", profiles[0])
	}
}
