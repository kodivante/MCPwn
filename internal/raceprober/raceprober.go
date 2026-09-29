package raceprober

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/client"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

const (
	concurrentRequests = 5
	raceMarker         = "mcpwnRaceProbe"
	defaultWindow      = 3 * time.Second
	handshakeID        = 0
	callID             = 1
)

type TransportSource func() (client.Transport, error)

type Options struct {
	Timeout time.Duration
}

type Engine struct {
	source  TransportSource
	tools   []schema.Tool
	timeout time.Duration
}

type probeResult struct {
	err error
}

func NewEngine(source TransportSource, tools []schema.Tool, options Options) *Engine {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultWindow
	}
	return &Engine{source: source, tools: tools, timeout: timeout}
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
	if err := handshake(transport); err != nil {
		return probeResult{err: err}
	}
	arguments, err := json.Marshal(map[string]string{param: raceMarker})
	if err != nil {
		return probeResult{err: err}
	}
	params, err := json.Marshal(client.CallToolParams{Name: toolName, Arguments: arguments})
	if err != nil {
		return probeResult{err: err}
	}
	request := client.JSONRPCMessage{JSONRPC: "2.0", ID: rawID(callID), Method: "tools/call", Params: params}
	if err := transport.Send(request); err != nil {
		return probeResult{err: err}
	}
	response, timedOut, err := e.awaitResponse(transport, callID)
	if timedOut || err != nil {
		return probeResult{err: fmt.Errorf("race probe call failed: %w", err)}
	}
	if response.Error != nil {
		return probeResult{err: fmt.Errorf("rpc error %d: %s", response.Error.Code, response.Error.Message)}
	}
	return probeResult{}
}

func handshake(transport client.Transport) error {
	initializeParams := json.RawMessage(`{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"MCPwn race probe","version":"1.0.0"}}`)
	message := client.JSONRPCMessage{JSONRPC: "2.0", ID: rawID(handshakeID), Method: "initialize", Params: initializeParams}
	if err := transport.Send(message); err != nil {
		return fmt.Errorf("race handshake failed: %w", err)
	}
	if _, timedOut, err := awaitInitResponse(transport); timedOut || err != nil {
		return fmt.Errorf("race handshake response failed: %w", err)
	}
	initialized := client.JSONRPCMessage{JSONRPC: "2.0", Method: "notifications/initialized"}
	return transport.Send(initialized)
}

type readOutcome struct {
	msg client.JSONRPCMessage
	err error
}

func awaitInitResponse(transport client.Transport) (client.JSONRPCMessage, bool, error) {
	outcome := make(chan readOutcome, 1)
	go func() {
		msg, err := transport.Receive()
		outcome <- readOutcome{msg: msg, err: err}
	}()
	select {
	case res := <-outcome:
		if res.err != nil {
			return client.JSONRPCMessage{}, false, res.err
		}
		if string(res.msg.ID) != strconv.Itoa(handshakeID) {
			return awaitInitResponse(transport)
		}
		return res.msg, false, nil
	case <-time.After(defaultWindow):
		return client.JSONRPCMessage{}, true, fmt.Errorf("handshake response timed out")
	}
}

func (e *Engine) awaitResponse(transport client.Transport, id int) (client.JSONRPCMessage, bool, error) {
	for {
		outcome := make(chan readOutcome, 1)
		go func() {
			msg, err := transport.Receive()
			outcome <- readOutcome{msg: msg, err: err}
		}()
		select {
		case res := <-outcome:
			if res.err != nil {
				return client.JSONRPCMessage{}, false, res.err
			}
			if string(res.msg.ID) != strconv.Itoa(id) {
				continue
			}
			return res.msg, false, nil
		case <-time.After(e.timeout):
			return client.JSONRPCMessage{}, true, fmt.Errorf("race probe timed out")
		}
	}
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

func rawID(id int) json.RawMessage {
	return json.RawMessage(strconv.Itoa(id))
}
