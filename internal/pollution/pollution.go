package pollution

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

const (
	defaultTimeout  = 10 * time.Second
	pollutionRuleID = "MassAssignment01"
	extraProperty   = "mcpwnProbeExtra"
	extraValue      = "mcpwnPollutionMarker"
	probeValue      = "mcpwnProbeValue"
)

type ToolCaller interface {
	CallTool(name string, arguments json.RawMessage) (json.RawMessage, error)
}

type Options struct {
	Timeout time.Duration
}

type Engine struct {
	caller  ToolCaller
	tools   []schema.Tool
	timeout time.Duration
}

func NewEngine(caller ToolCaller, tools []schema.Tool, options Options) *Engine {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Engine{caller: caller, tools: tools, timeout: timeout}
}

func (e *Engine) ConfirmFindings(findings []auditor.Finding) []auditor.Finding {
	results := make([]auditor.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.RuleID == pollutionRuleID {
			finding = e.confirmFinding(finding)
		}
		results = append(results, finding)
	}
	return results
}

func (e *Engine) confirmFinding(finding auditor.Finding) auditor.Finding {
	tool, ok := e.toolByName(finding.TargetTool)
	if !ok {
		return finding
	}
	arguments, err := buildArguments(tool.InputSchema, finding.ParamPath)
	if err != nil {
		return finding
	}
	raw, timedOut, err := e.callWithTimeout(tool.Name, arguments)
	if timedOut || err != nil {
		return finding
	}
	if responseFailed(raw) {
		return finding
	}
	finding.Confirmed = true
	finding.Evidence = fmt.Sprintf("undeclared property %q accepted by %q in tool call arguments", extraProperty, tool.Name)
	return finding
}

func (e *Engine) toolByName(name string) (schema.Tool, bool) {
	for _, tool := range e.tools {
		if tool.Name == name {
			return tool, true
		}
	}
	return schema.Tool{}, false
}

func buildArguments(root schema.JSONSchema, targetPath string) (json.RawMessage, error) {
	chain := propertyChain(targetPath)
	if len(chain) == 0 {
		polluted := map[string]json.RawMessage{}
		for _, key := range root.Required {
			polluted[key] = benignValue(root.Properties[key])
		}
		polluted[extraProperty] = json.RawMessage(`"` + extraValue + `"`)
		return json.Marshal(polluted)
	}
	nested, err := buildNested(root, chain)
	if err != nil {
		return nil, err
	}
	return nested, nil
}

func buildNested(node schema.JSONSchema, chain []string) (json.RawMessage, error) {
	values := map[string]json.RawMessage{}
	for _, key := range node.Required {
		values[key] = benignValue(node.Properties[key])
	}
	key := chain[0]
	child, ok := node.Properties[key]
	if !ok {
		return nil, fmt.Errorf("pollution chain property %q missing from schema", key)
	}
	if len(chain) == 1 {
		nested, err := buildPollutedObject(child)
		if err != nil {
			return nil, err
		}
		values[key] = nested
		return json.Marshal(values)
	}
	nested, err := buildNested(child, chain[1:])
	if err != nil {
		return nil, err
	}
	values[key] = nested
	return json.Marshal(values)
}

func buildPollutedObject(node schema.JSONSchema) (json.RawMessage, error) {
	values := map[string]json.RawMessage{}
	for _, key := range node.Required {
		values[key] = benignValue(node.Properties[key])
	}
	values[extraProperty] = json.RawMessage(`"` + extraValue + `"`)
	return json.Marshal(values)
}

func benignValue(prop schema.JSONSchema) json.RawMessage {
	switch prop.Type {
	case "number", "integer":
		return json.RawMessage(`1`)
	case "boolean":
		return json.RawMessage(`false`)
	case "array":
		if prop.Items != nil {
			inner := benignValue(*prop.Items)
			return json.RawMessage("[" + string(inner) + "]")
		}
		return json.RawMessage(`[]`)
	case "object":
		values := map[string]json.RawMessage{}
		for _, key := range prop.Required {
			values[key] = benignValue(prop.Properties[key])
		}
		data, err := json.Marshal(values)
		if err != nil {
			return json.RawMessage(`{}`)
		}
		return data
	default:
		return json.RawMessage(`"` + probeValue + `"`)
	}
}

func propertyChain(paramPath string) []string {
	trimmed := strings.TrimSuffix(paramPath, ".items")
	segments := strings.Split(trimmed, ".properties[")
	if len(segments) == 1 {
		return nil
	}
	chain := make([]string, 0, len(segments)-1)
	for _, segment := range segments[1:] {
		chain = append(chain, strings.TrimSuffix(segment, "]"))
	}
	return chain
}

type probeContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type probeResponse struct {
	Content []probeContent `json:"content"`
	IsError bool           `json:"isError"`
}

func responseFailed(raw json.RawMessage) bool {
	var resp probeResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return true
	}
	return resp.IsError
}

type probeOutcome struct {
	raw json.RawMessage
	err error
}

func (e *Engine) callWithTimeout(toolName string, arguments json.RawMessage) (json.RawMessage, bool, error) {
	outcome := make(chan probeOutcome, 1)
	go func() {
		raw, err := e.caller.CallTool(toolName, arguments)
		outcome <- probeOutcome{raw: raw, err: err}
	}()
	select {
	case res := <-outcome:
		return res.raw, false, res.err
	case <-time.After(e.timeout):
		return nil, true, fmt.Errorf("pollution probe timed out after %s", e.timeout)
	}
}
