package sequencefuzz

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/capability"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

const (
	defaultTimeout  = 10 * time.Second
	idempotencyRule = "Idempotency01"
	driftRule       = "SequenceDrift01"
	maxDriftPairs   = 6
)

type ToolCaller interface {
	CallTool(name string, arguments json.RawMessage) (json.RawMessage, error)
}

type Options struct {
	Timeout time.Duration
}

type Engine struct {
	caller   ToolCaller
	tools    []schema.Tool
	profiles []capability.ToolCapability
	timeout  time.Duration
}

func NewEngine(caller ToolCaller, tools []schema.Tool, profiles []capability.ToolCapability, options Options) *Engine {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Engine{caller: caller, tools: tools, profiles: profiles, timeout: timeout}
}

func (e *Engine) Probe() []auditor.Finding {
	var findings []auditor.Finding
	findings = append(findings, e.idempotencyFindings()...)
	findings = append(findings, e.driftFindings()...)
	return findings
}

func (e *Engine) idempotencyFindings() []auditor.Finding {
	var findings []auditor.Finding
	for _, tool := range e.tools {
		if !e.hasCapability(tool.Name, capability.State) {
			continue
		}
		arguments, err := benignArguments(tool)
		if err != nil {
			continue
		}
		first := e.call(tool.Name, arguments)
		second := e.call(tool.Name, arguments)
		if first == nil || second == nil {
			continue
		}
		if shapeChanged(first, second) {
			findings = append(findings, auditor.Finding{
				Severity:    auditor.SeverityMedium,
				RuleID:      idempotencyRule,
				TargetTool:  tool.Name,
				ParamPath:   "sequence",
				Description: "Identical sequential calls to a state-mutating tool produced different response structures",
				Remediation: "Make state-mutating operations idempotent or explicitly reject duplicate sequential requests.",
				Confirmed:   true,
				Evidence:    "two identical benign calls returned structurally different responses",
			})
		}
	}
	return findings
}

func (e *Engine) driftFindings() []auditor.Finding {
	var findings []auditor.Finding
	mutators := e.toolsWithCapability(capability.State)
	observations := e.toolsWithCapability(capability.Resource)
	if len(observations) == 0 {
		observations = e.toolsWithCapability(capability.Filesystem)
	}
	pairs := 0
	for _, mutator := range mutators {
		for _, observer := range observations {
			if pairs >= maxDriftPairs {
				return findings
			}
			if mutator.Name == observer.Name {
				continue
			}
			pairs++
			if finding, ok := e.probePair(mutator, observer); ok {
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

func (e *Engine) probePair(mutator, observer schema.Tool) (auditor.Finding, bool) {
	observerArgs, err := benignArguments(observer)
	if err != nil {
		return auditor.Finding{}, false
	}
	baseline := e.call(observer.Name, observerArgs)
	mutatorArgs, err := benignArguments(mutator)
	if err != nil {
		return auditor.Finding{}, false
	}
	if e.call(mutator.Name, mutatorArgs) == nil {
		return auditor.Finding{}, false
	}
	after := e.call(observer.Name, observerArgs)
	if baseline == nil || after == nil {
		return auditor.Finding{}, false
	}
	if !shapeChanged(baseline, after) {
		return auditor.Finding{}, false
	}
	return auditor.Finding{
		Severity:    auditor.SeverityMedium,
		RuleID:      driftRule,
		TargetTool:  observer.Name,
		ParamPath:   "sequence",
		Description: fmt.Sprintf("Benign call to %s changed the state observed through %s", mutator.Name, observer.Name),
		Remediation: "Scope state mutations to the tool contract: unrelated tools must not observe each other's side effects.",
		Confirmed:   true,
		Evidence:    fmt.Sprintf("response structure of %s changed after a benign call to %s", observer.Name, mutator.Name),
	}, true
}

func (e *Engine) call(toolName string, arguments json.RawMessage) []byte {
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

func (e *Engine) hasCapability(toolName, capabilityName string) bool {
	for _, profile := range e.profiles {
		if profile.Tool == toolName && capability.Contains(profile, capabilityName) {
			return true
		}
	}
	return false
}

func (e *Engine) toolsWithCapability(capabilityName string) []schema.Tool {
	var matched []schema.Tool
	for _, tool := range e.tools {
		if e.hasCapability(tool.Name, capabilityName) {
			matched = append(matched, tool)
		}
	}
	return matched
}

func benignArguments(tool schema.Tool) (json.RawMessage, error) {
	values := make(map[string]string)
	for key, prop := range tool.InputSchema.Properties {
		if prop.Type == "string" {
			values[key] = "mcpwnSeqValue"
		}
	}
	return json.Marshal(values)
}

func shapeChanged(first, second []byte) bool {
	return string(first) != string(second)
}
