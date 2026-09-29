package fuzzer

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

const (
	defaultTimeout = 10 * time.Second
	maxAttempts    = 2
)

type ToolCaller interface {
	CallTool(name string, arguments json.RawMessage) (json.RawMessage, error)
}

type Options struct {
	Timeout  time.Duration
	Payloads []Payload
}

type Engine struct {
	caller   ToolCaller
	payloads []Payload
	timeout  time.Duration
	aborted  bool
}

func NewEngine(caller ToolCaller, options Options) (*Engine, error) {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	payloads := options.Payloads
	if len(payloads) == 0 {
		payloads = BuiltinPayloads()
	}
	for _, payload := range payloads {
		if err := ValidatePayload(payload); err != nil {
			return nil, err
		}
	}
	return &Engine{caller: caller, payloads: payloads, timeout: timeout}, nil
}

func (e *Engine) ConfirmFindings(findings []auditor.Finding) []auditor.Finding {
	results := make([]auditor.Finding, 0, len(findings))
	for _, finding := range findings {
		if e.aborted {
			results = append(results, finding)
			continue
		}
		results = append(results, e.confirmFinding(finding))
	}
	return results
}

func (e *Engine) confirmFinding(finding auditor.Finding) auditor.Finding {
	key := argumentKey(finding.ParamPath)
	if key == "" {
		return finding
	}
	for _, payload := range e.payloads {
		if payload.RuleID != finding.RuleID {
			continue
		}
		if evidence, confirmed := e.runProbe(finding.TargetTool, key, payload); confirmed {
			finding.Confirmed = true
			finding.Evidence = evidence
			return finding
		}
		if e.aborted {
			return finding
		}
	}
	return finding
}

func (e *Engine) runProbe(toolName, key string, payload Payload) (string, bool) {
	for attempt := 0; attempt < maxAttempts; attempt++ {
		evidence, confirmed := e.attemptProbe(toolName, key, payload)
		if confirmed {
			return evidence, true
		}
		if e.aborted {
			return "", false
		}
	}
	return "", false
}

func (e *Engine) attemptProbe(toolName, key string, payload Payload) (string, bool) {
	render, err := renderProbe(payload)
	if err != nil {
		return "", false
	}
	defer render.cleanup()

	arguments, err := json.Marshal(map[string]string{key: render.command})
	if err != nil {
		return "", false
	}

	start := time.Now()
	raw, timedOut, err := e.callWithTimeout(toolName, arguments)
	if timedOut {
		e.aborted = true
		return "", false
	}
	if err != nil {
		return "", false
	}

	return evaluateProbe(payload, render, responseText(raw), time.Since(start))
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
		return nil, true, fmt.Errorf("probe timed out after %s", e.timeout)
	}
}

func evaluateProbe(payload Payload, render probeRender, response string, elapsed time.Duration) (string, bool) {
	if payload.Expect != "" && strings.Contains(response, render.expect) {
		return fmt.Sprintf("marker %q found in tool response", render.marker), true
	}
	if payload.MinDelay > 0 && elapsed >= payload.MinDelay {
		return fmt.Sprintf("response delayed %s (threshold %s)", elapsed.Round(time.Millisecond), payload.MinDelay), true
	}
	return "", false
}
