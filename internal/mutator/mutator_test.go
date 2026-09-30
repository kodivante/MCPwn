package mutator

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

type scriptedCaller struct {
	respond func(payload string) (json.RawMessage, error)
}

func (s scriptedCaller) CallTool(name string, arguments json.RawMessage) (json.RawMessage, error) {
	var params struct {
		Cmd string `json:"cmd"`
	}
	if err := json.Unmarshal(arguments, &params); err != nil {
		return nil, err
	}
	return s.respond(params.Cmd)
}

func execTool() schema.Tool {
	return schema.Tool{
		Name: "runCommand",
		InputSchema: schema.JSONSchema{
			Type:       "object",
			Properties: map[string]schema.JSONSchema{"cmd": {Type: "string"}},
		},
	}
}

func echoResponse(payload string) json.RawMessage {
	return json.RawMessage(`{"content":[{"type":"text","text":"` + payload + `"}]}`)
}

func TestProbeFlagsEvaluatedSubstitution(t *testing.T) {
	caller := scriptedCaller{respond: func(payload string) (json.RawMessage, error) {
		if strings.HasPrefix(payload, "$(echo mcpwnMut00") {
			return json.RawMessage(`{"content":[{"type":"text","text":"output: mcpwnMut00"}]}`), nil
		}
		return echoResponse(payload), nil
	}}
	engine := NewEngine(caller, []schema.Tool{execTool()}, Options{Timeout: 500 * time.Millisecond})
	findings := engine.Probe()
	if len(findings) != 1 {
		t.Fatalf("expected 1 executed-substitution finding, got %+v", findings)
	}
	if findings[0].RuleID != "MutationDiff01" || findings[0].Severity != auditor.SeverityHigh {
		t.Errorf("unexpected finding: %+v", findings[0])
	}
	if !findings[0].Confirmed {
		t.Error("executed substitution must be confirmed")
	}
}

func TestProbeIgnoresLiteralReflection(t *testing.T) {
	caller := scriptedCaller{respond: func(payload string) (json.RawMessage, error) {
		return echoResponse(payload), nil
	}}
	engine := NewEngine(caller, []schema.Tool{execTool()}, Options{Timeout: 500 * time.Millisecond})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("literal reflection must not be flagged, got %+v", findings)
	}
}

func TestProbeIgnoresUnrelatedResponses(t *testing.T) {
	caller := scriptedCaller{respond: func(payload string) (json.RawMessage, error) {
		return json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`), nil
	}}
	engine := NewEngine(caller, []schema.Tool{execTool()}, Options{Timeout: 500 * time.Millisecond})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("static responses must not be flagged, got %+v", findings)
	}
}

func TestProbeFailingCaller(t *testing.T) {
	caller := scriptedCaller{respond: func(payload string) (json.RawMessage, error) {
		return nil, errors.New("down")
	}}
	engine := NewEngine(caller, []schema.Tool{execTool()}, Options{Timeout: 500 * time.Millisecond})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings on failing caller, got %+v", findings)
	}
}

func TestProbeSkipsNonStringTools(t *testing.T) {
	tool := schema.Tool{
		Name:        "addNumbers",
		InputSchema: schema.JSONSchema{Type: "object", Properties: map[string]schema.JSONSchema{"a": {Type: "number"}}},
	}
	engine := NewEngine(scriptedCaller{respond: func(string) (json.RawMessage, error) { return nil, errors.New("x") }}, []schema.Tool{tool}, Options{})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings without string params, got %+v", findings)
	}
}
