package raceprober

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/client"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

const (
	concurrentRequests = 5
	raceMarker         = "mcpwnRaceProbe"
)

type TransportSource func() (client.Transport, error)

type Options struct{}

type Engine struct {
	source TransportSource
	tools  []schema.Tool
}

type probeResult struct {
	err error
}

func NewEngine(source TransportSource, tools []schema.Tool, options Options) *Engine {
	return &Engine{source: source, tools: tools}
}

func (e *Engine) Probe() []auditor.Finding {
	var findings []auditor.Finding
	for _, tool := range e.tools {
		param, ok := firstStringParam(tool)
		if !ok {
			continue
		}
		if finding, ok := e.probeTool(tool.Name, param); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func (e *Engine) probeTool(toolName, param string) (auditor.Finding, bool) {
	results := make([]probeResult, concurrentRequests)
	var wg sync.WaitGroup
	for slot := 0; slot < concurrentRequests; slot++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			results[slot] = e.singleCall(toolName, param)
		}(slot)
	}
	wg.Wait()

	successes, failures := 0, 0
	for _, result := range results {
		if result.err == nil {
			successes++
			continue
		}
		failures++
	}
	if successes > 0 && failures > 0 {
		return raceFinding(toolName, successes, failures), true
	}
	return auditor.Finding{}, false
}

func (e *Engine) singleCall(toolName, param string) probeResult {
	transport, err := e.source()
	if err != nil {
		return probeResult{err: err}
	}
	defer transport.Close()

	session := client.NewSession(transport)
	if err := session.Initialize(); err != nil {
		return probeResult{err: err}
	}

	arguments, err := json.Marshal(map[string]string{param: raceMarker})
	if err != nil {
		return probeResult{err: err}
	}
	if _, err := session.CallTool(toolName, arguments); err != nil {
		return probeResult{err: err}
	}
	return probeResult{}
}

func raceFinding(toolName string, successes, failures int) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityMedium,
		RuleID:      "RaceCondition01",
		TargetTool:  toolName,
		ParamPath:   "concurrency",
		Description: fmt.Sprintf("Identical concurrent requests produced inconsistent outcomes (%d succeeded, %d failed)", successes, failures),
		Remediation: "Serialize state-mutating tool calls with proper locking or idempotency keys so identical concurrent requests behave consistently.",
		Confirmed:   true,
		Evidence:    fmt.Sprintf("%d of %d identical concurrent calls failed while the rest succeeded", failures, concurrentRequests),
	}
}

func firstStringParam(tool schema.Tool) (string, bool) {
	keys := make([]string, 0, len(tool.InputSchema.Properties))
	for key := range tool.InputSchema.Properties {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if tool.InputSchema.Properties[key].Type == "string" {
			return key, true
		}
	}
	return "", false
}
