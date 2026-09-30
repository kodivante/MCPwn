package mutator

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

const (
	defaultTimeout = 10 * time.Second
	ruleID         = "MutationDiff01"
	markerPrefix   = "mcpwnMut"
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

type substitutionOperator struct {
	label   string
	wrapper string
	render  func(marker string) string
}

func substitutionOperators() []substitutionOperator {
	return []substitutionOperator{
		{
			label:   "command substitution",
			wrapper: "$(echo",
			render:  func(marker string) string { return "$(echo " + marker + ")" },
		},
		{
			label:   "backtick substitution",
			wrapper: "`echo",
			render:  func(marker string) string { return "`echo " + marker + "`" },
		},
		{
			label:   "variable expansion",
			wrapper: "${",
			render:  func(marker string) string { return "${" + marker + "}" },
		},
	}
}

func NewEngine(caller ToolCaller, tools []schema.Tool, options Options) *Engine {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Engine{caller: caller, tools: tools, timeout: timeout}
}

func (e *Engine) Probe() []auditor.Finding {
	var findings []auditor.Finding
	for index, tool := range e.tools {
		param, ok := firstStringParam(tool)
		if !ok {
			continue
		}
		if finding, ok := e.probeTool(tool, param, index); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func (e *Engine) probeTool(tool schema.Tool, param string, index int) (auditor.Finding, bool) {
	marker := fmt.Sprintf("%s%02d", markerPrefix, index)
	for _, operator := range substitutionOperators() {
		payload := operator.render(marker)
		response := e.call(tool.Name, param, payload)
		if response == nil {
			continue
		}
		text := responseText(response)
		if strings.Contains(text, operator.wrapper) {
			continue
		}
		if strings.Contains(text, marker) {
			return executedFinding(tool.Name, param, operator.label, marker), true
		}
	}
	return auditor.Finding{}, false
}

func (e *Engine) call(toolName, param, value string) []byte {
	arguments, err := json.Marshal(map[string]string{param: value})
	if err != nil {
		return nil
	}
	done := make(chan callResult, 1)
	go func() {
		raw, err := e.caller.CallTool(toolName, arguments)
		done <- callResult{raw: raw, err: err}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			return nil
		}
		return res.raw
	case <-time.After(e.timeout):
		return nil
	}
}

type callResult struct {
	raw json.RawMessage
	err error
}

func responseText(raw []byte) string {
	var parsed struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return string(raw)
	}
	texts := make([]string, 0, len(parsed.Content))
	for _, content := range parsed.Content {
		texts = append(texts, content.Text)
	}
	return strings.Join(texts, "\n")
}

func executedFinding(toolName, param, operator, marker string) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityHigh,
		RuleID:      ruleID,
		TargetTool:  toolName,
		ParamPath:   "inputSchema.properties[" + param + "]",
		Description: fmt.Sprintf("Server evaluated %s on parameter '%s', proving the input reaches a command interpreter", operator, param),
		Remediation: "Never pass tool input into a shell: use argument arrays without shell interpolation, or allowlist exact values.",
		Confirmed:   true,
		Evidence:    fmt.Sprintf("payload for %q evaluated: marker %s returned without its wrapper syntax", operator, marker),
	}
}

func firstStringParam(tool schema.Tool) (string, bool) {
	for key, prop := range tool.InputSchema.Properties {
		if prop.Type == "string" {
			return key, true
		}
	}
	return "", false
}
