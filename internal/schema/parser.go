package schema

import (
	"encoding/json"
	"fmt"
)

type Tool struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	InputSchema JSONSchema `json:"inputSchema"`
}

type JSONSchema struct {
	Type                 string                `json:"type"`
	Properties           map[string]JSONSchema `json:"properties,omitempty"`
	Required             []string              `json:"required,omitempty"`
	Description          string                `json:"description,omitempty"`
	Enum                 []json.RawMessage     `json:"enum,omitempty"`
	Items                *JSONSchema           `json:"items,omitempty"`
	AdditionalProperties *bool                 `json:"additionalProperties,omitempty"`
}

func ParseTool(data []byte) (Tool, error) {
	var tool Tool
	if err := json.Unmarshal(data, &tool); err != nil {
		return Tool{}, fmt.Errorf("tool parsing failed: %w", err)
	}
	return tool, nil
}
