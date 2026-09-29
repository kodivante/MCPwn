package client

import (
	"encoding/json"
	"fmt"

	"github.com/kodivante/MCPwn/v3/internal/version"
)

const ProtocolVersion = "2024-11-05"

const clientName = "MCPwn"

type ClientCapabilities struct {
	Experimental map[string]json.RawMessage `json:"experimental,omitempty"`
	Roots        json.RawMessage            `json:"roots,omitempty"`
	Sampling     json.RawMessage            `json:"sampling,omitempty"`
}

type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type InitializeParams struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      ClientInfo         `json:"clientInfo"`
}

type ServerCapabilities struct {
	Experimental map[string]json.RawMessage `json:"experimental,omitempty"`
	Logging      json.RawMessage            `json:"logging,omitempty"`
	Prompts      json.RawMessage            `json:"prompts,omitempty"`
	Resources    json.RawMessage            `json:"resources,omitempty"`
	Tools        json.RawMessage            `json:"tools,omitempty"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ServerInfo         `json:"serverInfo"`
}

func (s *Session) Initialize() error {
	params, err := json.Marshal(InitializeParams{
		ProtocolVersion: ProtocolVersion,
		Capabilities:    ClientCapabilities{},
		ClientInfo:      ClientInfo{Name: clientName, Version: version.Version},
	})
	if err != nil {
		return fmt.Errorf("initialize params serialization failed: %w", err)
	}

	resp, err := s.request("initialize", params)
	if err != nil {
		return fmt.Errorf("initialize failed: %w", err)
	}

	var result InitializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return fmt.Errorf("initialize result parsing failed: %w", err)
	}

	return s.notify("notifications/initialized")
}
