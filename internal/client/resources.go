package client

import (
	"encoding/json"
	"fmt"
)

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type ResourcesListResult struct {
	Resources []Resource `json:"resources"`
}

type ReadResourceParams struct {
	URI string `json:"uri"`
}

type ReadResourceResult struct {
	Contents []json.RawMessage `json:"contents"`
}

func (s *Session) ListResources() ([]Resource, error) {
	resp, err := s.request("resources/list", nil)
	if err != nil {
		return nil, fmt.Errorf("resources listing failed: %w", err)
	}

	var result ResourcesListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("resources list parsing failed: %w", err)
	}
	return result.Resources, nil
}

func (s *Session) ReadResource(uri string) (ReadResourceResult, error) {
	params, err := json.Marshal(ReadResourceParams{URI: uri})
	if err != nil {
		return ReadResourceResult{}, fmt.Errorf("resource read params serialization failed: %w", err)
	}

	resp, err := s.request("resources/read", params)
	if err != nil {
		return ReadResourceResult{}, fmt.Errorf("resource read %s failed: %w", uri, err)
	}

	var result ReadResourceResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return ReadResourceResult{}, fmt.Errorf("resource read parsing failed: %w", err)
	}
	return result, nil
}
