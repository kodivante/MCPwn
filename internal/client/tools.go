package client

import (
	"encoding/json"
	"fmt"

	"github.com/kodivante/MCPwn/v3/internal/schema"
)

type ToolsListResult struct {
	Tools []json.RawMessage `json:"tools"`
}

type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

func (s *Session) ListTools() ([]schema.Tool, error) {
	resp, err := s.request("tools/list", nil)
	if err != nil {
		return nil, fmt.Errorf("tools listing failed: %w", err)
	}

	var result ToolsListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("tools list parsing failed: %w", err)
	}

	tools := make([]schema.Tool, 0, len(result.Tools))
	for _, raw := range result.Tools {
		tool, err := schema.ParseTool(raw)
		if err != nil {
			return nil, fmt.Errorf("tool parsing failed: %w", err)
		}
		tools = append(tools, tool)
	}
	return tools, nil
}

func (s *Session) CallTool(name string, arguments json.RawMessage) (json.RawMessage, error) {
	params, err := json.Marshal(CallToolParams{Name: name, Arguments: arguments})
	if err != nil {
		return nil, fmt.Errorf("tool call params serialization failed: %w", err)
	}

	resp, err := s.request("tools/call", params)
	if err != nil {
		return nil, fmt.Errorf("tool call %s failed: %w", name, err)
	}
	return resp.Result, nil
}
