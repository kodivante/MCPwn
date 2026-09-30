package sequencefuzz

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/capability"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

type scriptedCaller struct {
	calls   int
	scripts map[string]func(call int) (json.RawMessage, error)
}

func (s *scriptedCaller) CallTool(name string, arguments json.RawMessage) (json.RawMessage, error) {
	s.calls++
	if script, ok := s.scripts[name]; ok {
		return script(s.calls)
	}
	return []byte(`{"content":[{"type":"text","text":"stable"}]}`), nil
}

func stateTool() schema.Tool {
	return schema.Tool{
		Name: "saveRecord",
		InputSchema: schema.JSONSchema{
			Type:       "object",
			Properties: map[string]schema.JSONSchema{"record": {Type: "string"}},
		},
	}
}

func observerTool() schema.Tool {
	return schema.Tool{
		Name: "listRecords",
		InputSchema: schema.JSONSchema{
			Type:       "object",
			Properties: map[string]schema.JSONSchema{"path": {Type: "string"}},
		},
	}
}

func profiles() []capability.ToolCapability {
	return []capability.ToolCapability{
		{Tool: "saveRecord", Capabilities: []string{capability.State}},
		{Tool: "listRecords", Capabilities: []string{capability.Filesystem}},
	}
}

func TestIdempotencyViolation(t *testing.T) {
	caller := &scriptedCaller{scripts: map[string]func(int) (json.RawMessage, error){
		"saveRecord": func(call int) (json.RawMessage, error) {
			if call >= 2 {
				return []byte(`{"content":[{"type":"text","text":"already saved"}],"isError":true}`), nil
			}
			return []byte(`{"content":[{"type":"text","text":"saved"}]}`), nil
		},
	}}
	engine := NewEngine(caller, []schema.Tool{stateTool()}, profiles(), Options{Timeout: 500 * time.Millisecond})
	findings := engine.Probe()
	if len(findings) != 1 {
		t.Fatalf("expected 1 idempotency finding, got %+v", findings)
	}
	if findings[0].RuleID != "Idempotency01" || findings[0].TargetTool != "saveRecord" {
		t.Errorf("unexpected finding: %+v", findings[0])
	}
	if !findings[0].Confirmed {
		t.Error("idempotency finding must be confirmed")
	}
}

func TestIdempotencyCleanTool(t *testing.T) {
	caller := &scriptedCaller{}
	engine := NewEngine(caller, []schema.Tool{stateTool()}, profiles(), Options{Timeout: 500 * time.Millisecond})
	for _, finding := range engine.Probe() {
		if finding.RuleID == "Idempotency01" {
			t.Errorf("stable tool must not flag idempotency: %+v", finding)
		}
	}
}

func TestCrossToolDrift(t *testing.T) {
	mutated := false
	caller := &scriptedCaller{scripts: map[string]func(int) (json.RawMessage, error){
		"saveRecord": func(call int) (json.RawMessage, error) {
			if call >= 3 {
				mutated = true
			}
			return []byte(`{"content":[{"type":"text","text":"saved"}]}`), nil
		},
		"listRecords": func(call int) (json.RawMessage, error) {
			if mutated {
				return []byte(`{"content":[{"type":"text","text":"record: mcpwnSeqValue"}]}`), nil
			}
			return []byte(`{"content":[{"type":"text","text":"empty"}]}`), nil
		},
	}}
	engine := NewEngine(caller, []schema.Tool{stateTool(), observerTool()}, profiles(), Options{Timeout: 500 * time.Millisecond})
	findings := engine.Probe()
	var drift *auditor.Finding
	for i := range findings {
		if findings[i].RuleID == "SequenceDrift01" {
			drift = &findings[i]
		}
	}
	if drift == nil {
		t.Fatalf("expected sequence drift finding, got %+v", findings)
	}
	if drift.TargetTool != "listRecords" || !drift.Confirmed {
		t.Errorf("unexpected finding shape: %+v", *drift)
	}
}

func TestCrossToolCleanPair(t *testing.T) {
	caller := &scriptedCaller{}
	engine := NewEngine(caller, []schema.Tool{stateTool(), observerTool()}, profiles(), Options{Timeout: 500 * time.Millisecond})
	for _, finding := range engine.Probe() {
		if finding.RuleID == "SequenceDrift01" {
			t.Errorf("independent tools must not flag drift: %+v", finding)
		}
	}
}

func TestFailingCallerYieldsNothing(t *testing.T) {
	caller := &scriptedCaller{scripts: map[string]func(int) (json.RawMessage, error){
		"saveRecord": func(call int) (json.RawMessage, error) {
			return nil, errors.New("down")
		},
	}}
	engine := NewEngine(caller, []schema.Tool{stateTool()}, profiles(), Options{Timeout: 500 * time.Millisecond})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings on failing caller, got %+v", findings)
	}
}

func TestNoStateToolsNoFindings(t *testing.T) {
	tool := schema.Tool{
		Name: "greet",
		InputSchema: schema.JSONSchema{
			Type:       "object",
			Properties: map[string]schema.JSONSchema{"name": {Type: "string"}},
		},
	}
	engine := NewEngine(&scriptedCaller{}, []schema.Tool{tool}, nil, Options{})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings without state tools, got %+v", findings)
	}
}
