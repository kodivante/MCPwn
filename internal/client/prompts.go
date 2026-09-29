package client

import (
	"encoding/json"
	"fmt"
)

type PromptMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

type PromptsListResult struct {
	Prompts []Prompt `json:"prompts"`
}

type GetPromptParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

type GetPromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

func (s *Session) ListPrompts() ([]Prompt, error) {
	resp, err := s.request("prompts/list", nil)
	if err != nil {
		return nil, fmt.Errorf("prompts listing failed: %w", err)
	}

	var result PromptsListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("prompts list parsing failed: %w", err)
	}
	return result.Prompts, nil
}

func (s *Session) GetPrompt(name string, arguments map[string]string) (GetPromptResult, error) {
	params, err := json.Marshal(GetPromptParams{Name: name, Arguments: arguments})
	if err != nil {
		return GetPromptResult{}, fmt.Errorf("prompt get params serialization failed: %w", err)
	}

	resp, err := s.request("prompts/get", params)
	if err != nil {
		return GetPromptResult{}, fmt.Errorf("prompt get %s failed: %w", name, err)
	}

	var result GetPromptResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return GetPromptResult{}, fmt.Errorf("prompt get parsing failed: %w", err)
	}
	return result, nil
}
