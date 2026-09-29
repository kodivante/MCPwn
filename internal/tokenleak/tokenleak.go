package tokenleak

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

const defaultTimeout = 10 * time.Second

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

func (e *Engine) ProbeTools() []auditor.Finding {
	var findings []auditor.Finding
	for _, tool := range e.tools {
		findings = append(findings, e.probeTool(tool)...)
	}
	return findings
}

func (e *Engine) probeTool(tool schema.Tool) []auditor.Finding {
	arguments, err := buildArguments(tool.InputSchema)
	if err != nil {
		return nil
	}
	raw, err := e.callWithTimeout(tool.Name, arguments)
	if err != nil {
		if finding, ok := errorLeak(err.Error(), tool.Name); ok {
			return []auditor.Finding{finding}
		}
		return nil
	}
	if finding, ok := responseLeak(string(raw), tool.Name); ok {
		return []auditor.Finding{finding}
	}
	return nil
}

func buildArguments(root schema.JSONSchema) (json.RawMessage, error) {
	if len(root.Properties) == 0 {
		return json.Marshal(map[string]string{})
	}
	values := make(map[string]json.RawMessage, len(root.Properties))
	for key, prop := range root.Properties {
		if required(root, key) {
			values[key] = benignValue(prop)
		}
	}
	return json.Marshal(values)
}

func required(root schema.JSONSchema, key string) bool {
	for _, name := range root.Required {
		if name == key {
			return true
		}
	}
	return false
}

func benignValue(prop schema.JSONSchema) json.RawMessage {
	switch prop.Type {
	case "number", "integer":
		return json.RawMessage("1")
	case "boolean":
		return json.RawMessage("false")
	case "array":
		return json.RawMessage("[]")
	case "object":
		return json.RawMessage("{}")
	default:
		return json.RawMessage(`"mcpwnProbeValue"`)
	}
}

func errorLeak(errorText, toolName string) (auditor.Finding, bool) {
	lowered := strings.ToLower(errorText)
	for _, marker := range leakMarkers {
		if strings.Contains(lowered, marker) {
			return leakFinding(toolName, errorText, fmt.Sprintf("error message contains %q", marker)), true
		}
	}
	return auditor.Finding{}, false
}

func responseLeak(response, toolName string) (auditor.Finding, bool) {
	lowered := strings.ToLower(response)
	for _, marker := range leakMarkers {
		if strings.Contains(lowered, marker) {
			return leakFinding(toolName, truncate(response, 200), fmt.Sprintf("tool response contains %q", marker)), true
		}
	}
	return auditor.Finding{}, false
}

var leakMarkers = []string{
	"sk-", "api_key", "apikey",
	"secret", "password",
	"bearer ", "token=",
	"authorization:",
	"aws_access_key", "aws_secret",
	"private_key", "-----begin",
	"ghp_", "credential",
	"session_id",
	"jwt ",
	"basic ",
}

func leakFinding(toolName, sample, evidence string) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityCritical,
		RuleID:      "TokenLeak01",
		TargetTool:  toolName,
		ParamPath:   "response",
		Description: "Credentials or secrets detected in tool response or error messages",
		Remediation: "Never return credentials, API keys, tokens or internal secrets in tool responses or error messages. Redact all sensitive data before sending to the LLM.",
		Confirmed:   true,
		Evidence:    fmt.Sprintf("%s (sample: %q)", evidence, sample),
	}
}

func truncate(text string, max int) string {
	if len(text) <= max {
		return text
	}
	return text[:max] + "..."
}

type probeOutcome struct {
	raw json.RawMessage
	err error
}

func (e *Engine) callWithTimeout(toolName string, arguments json.RawMessage) (json.RawMessage, error) {
	outcome := make(chan probeOutcome, 1)
	go func() {
		raw, err := e.caller.CallTool(toolName, arguments)
		outcome <- probeOutcome{raw: raw, err: err}
	}()
	select {
	case res := <-outcome:
		return res.raw, res.err
	case <-time.After(e.timeout):
		return nil, fmt.Errorf("token leak probe timed out after %s", e.timeout)
	}
}
