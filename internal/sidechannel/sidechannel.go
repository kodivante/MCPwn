package sidechannel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

const (
	defaultTimeout = 10 * time.Second
	sampleCount    = 3
	timingFactor   = 3.0
	timingFloor    = 200 * time.Millisecond
	sizeFactor     = 2.0
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

func (e *Engine) Probe() []auditor.Finding {
	var findings []auditor.Finding
	for _, tool := range e.tools {
		findings = append(findings, e.probeTool(tool)...)
	}
	return findings
}

func (e *Engine) probeTool(tool schema.Tool) []auditor.Finding {
	key := stringArgKey(tool)
	if key == "" {
		return nil
	}
	baseline := e.measure(tool.Name, key, "mcpwnBaseline")
	if baseline.err != nil || baseline.latency == 0 {
		return nil
	}
	if findings := e.checkTiming(tool, key, baseline); findings != nil {
		return findings
	}
	return e.checkDifferential(tool, key, baseline)
}

func (e *Engine) checkTiming(tool schema.Tool, key string, baseline probeSample) []auditor.Finding {
	worst := baseline
	for i := 0; i < sampleCount; i++ {
		sample := e.measure(tool.Name, key, timingPayload())
		if sample.err != nil {
			return nil
		}
		if sample.latency > worst.latency {
			worst = sample
		}
	}
	threshold := timingThreshold(baseline.latency)
	if worst.latency >= threshold {
		return []auditor.Finding{timingFinding(tool, baseline, worst)}
	}
	return nil
}

func (e *Engine) checkDifferential(tool schema.Tool, key string, baseline probeSample) []auditor.Finding {
	probe := e.measure(tool.Name, key, "'; sleep 2; echo '")
	if probe.err != nil {
		if isServerError(probe.err) && !isServerError(baseline.err) {
			return []auditor.Finding{errorDiffFinding(tool, probe)}
		}
		return nil
	}
	if probeSizeDiff(baseline, probe) {
		return []auditor.Finding{sizeDiffFinding(tool, baseline, probe)}
	}
	return nil
}

func probeSizeDiff(baseline, probe probeSample) bool {
	if len(baseline.raw) == 0 {
		return len(probe.raw) > 0
	}
	ratio := float64(len(probe.raw)) / float64(len(baseline.raw))
	return ratio >= sizeFactor || ratio <= 1.0/sizeFactor
}

func timingThreshold(base time.Duration) time.Duration {
	scaled := time.Duration(float64(base) * timingFactor)
	if scaled < timingFloor {
		return timingFloor
	}
	return scaled
}

func isServerError(err error) bool {
	return bytes.Contains([]byte(err.Error()), []byte("internal"))
}

func stringArgKey(tool schema.Tool) string {
	for name, prop := range tool.InputSchema.Properties {
		if prop.Type == "string" {
			return name
		}
	}
	return ""
}

func timingPayload() string {
	return "$(sleep 1)"
}

func (e *Engine) measure(toolName, key, value string) probeSample {
	arguments, err := json.Marshal(map[string]string{key: value})
	if err != nil {
		return probeSample{}
	}
	start := time.Now()
	raw, err := e.callWithTimeout(toolName, arguments)
	return probeSample{raw: raw, err: err, latency: time.Since(start)}
}

func timingFinding(tool schema.Tool, baseline, worst probeSample) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityMedium,
		RuleID:      "SideChannel01",
		TargetTool:  tool.Name,
		ParamPath:   "response.time",
		Description: "Timing side-channel suggests blind command or query injection",
		Remediation: "Use parameterized queries and avoid shell interpolation. Normalize response latency and reject inputs that alter server execution time.",
		Confirmed:   false,
		Evidence: fmt.Sprintf("baseline %s vs probe %s (threshold %s)",
			baseline.latency, worst.latency, timingThreshold(baseline.latency)),
	}
}

func errorDiffFinding(tool schema.Tool, probe probeSample) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityLow,
		RuleID:      "SideChannel02",
		TargetTool:  tool.Name,
		ParamPath:   "response.error",
		Description: "Error-based side-channel: probe input triggers server errors while benign input does not",
		Remediation: "Return uniform error messages that do not leak internal state. Validate and sanitize all string inputs.",
		Confirmed:   false,
		Evidence:    fmt.Sprintf("probe triggered server error: %q", truncate(probe.err.Error(), 160)),
	}
}

func sizeDiffFinding(tool schema.Tool, baseline, probe probeSample) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityLow,
		RuleID:      "SideChannel03",
		TargetTool:  tool.Name,
		ParamPath:   "response.size",
		Description: "Response size side-channel: probe input changes response length significantly",
		Remediation: "Normalize response sizes and avoid reflecting raw input in tool output.",
		Confirmed:   false,
		Evidence: fmt.Sprintf("baseline %d bytes vs probe %d bytes",
			len(baseline.raw), len(probe.raw)),
	}
}

func truncate(text string, max int) string {
	if len(text) <= max {
		return text
	}
	return text[:max] + "..."
}

type probeSample struct {
	raw     json.RawMessage
	err     error
	latency time.Duration
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
		return nil, fmt.Errorf("side-channel probe timed out after %s", e.timeout)
	}
}
