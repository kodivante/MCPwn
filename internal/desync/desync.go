package desync

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/client"
)

const (
	defaultTimeout = 10 * time.Second
	readWindow     = 3 * time.Second
)

type TransportSource func() (client.Transport, error)

type Options struct {
	Timeout time.Duration
}

type Engine struct {
	source  TransportSource
	timeout time.Duration
}

func NewEngine(source TransportSource, options Options) *Engine {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Engine{source: source, timeout: timeout}
}

func (e *Engine) Probe() []auditor.Finding {
	var findings []auditor.Finding
	scenarios := []struct {
		run func() (auditor.Finding, bool)
	}{
		{run: e.probeToolsListBeforeInitialize},
		{run: e.probeDoubleInitialize},
		{run: e.probeReInitializeAfterHandshake},
	}
	for _, scenario := range scenarios {
		if finding, ok := scenario.run(); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func (e *Engine) probeToolsListBeforeInitialize() (auditor.Finding, bool) {
	transport, err := e.source()
	if err != nil {
		return auditor.Finding{}, false
	}
	defer transport.Close()

	message := client.JSONRPCMessage{JSONRPC: "2.0", ID: rawID(1), Method: "tools/list"}
	if err := transport.Send(message); err != nil {
		return auditor.Finding{}, false
	}
	response, timedOut, err := e.awaitResponse(transport, 1)
	if timedOut || err != nil {
		return auditor.Finding{}, false
	}
	if response.Error == nil && response.Result != nil {
		return desyncFinding("server responded to tools/list before the initialize handshake"), true
	}
	return auditor.Finding{}, false
}

func (e *Engine) probeDoubleInitialize() (auditor.Finding, bool) {
	transport, err := e.source()
	if err != nil {
		return auditor.Finding{}, false
	}
	defer transport.Close()

	first, err := initializeMessage(1)
	if err != nil {
		return auditor.Finding{}, false
	}
	if err := transport.Send(first); err != nil {
		return auditor.Finding{}, false
	}
	if _, timedOut, err := e.awaitResponse(transport, 1); timedOut || err != nil {
		return auditor.Finding{}, false
	}

	second, err := initializeMessage(2)
	if err != nil {
		return auditor.Finding{}, false
	}
	if err := transport.Send(second); err != nil {
		return auditor.Finding{}, false
	}
	response, timedOut, err := e.awaitResponse(transport, 2)
	if timedOut || err != nil {
		return auditor.Finding{}, false
	}
	if response.Error == nil {
		return desyncFinding("server accepted a duplicate initialize request"), true
	}
	return auditor.Finding{}, false
}

func (e *Engine) probeReInitializeAfterHandshake() (auditor.Finding, bool) {
	transport, err := e.source()
	if err != nil {
		return auditor.Finding{}, false
	}
	defer transport.Close()

	first, err := initializeMessage(1)
	if err != nil {
		return auditor.Finding{}, false
	}
	if err := transport.Send(first); err != nil {
		return auditor.Finding{}, false
	}
	if _, timedOut, err := e.awaitResponse(transport, 1); timedOut || err != nil {
		return auditor.Finding{}, false
	}

	notification := client.JSONRPCMessage{JSONRPC: "2.0", Method: "notifications/initialized"}
	if err := transport.Send(notification); err != nil {
		return auditor.Finding{}, false
	}

	second, err := initializeMessage(2)
	if err != nil {
		return auditor.Finding{}, false
	}
	if err := transport.Send(second); err != nil {
		return auditor.Finding{}, false
	}
	response, timedOut, err := e.awaitResponse(transport, 2)
	if timedOut || err != nil {
		return auditor.Finding{}, false
	}
	if response.Error == nil {
		return desyncFinding("server accepted re-initialization after a completed handshake"), true
	}
	return auditor.Finding{}, false
}

func desyncFinding(description string) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityMedium,
		RuleID:      "StateDesync01",
		TargetTool:  "server",
		ParamPath:   "lifecycle",
		Description: description,
		Remediation: "Enforce the MCP lifecycle: reject requests before initialize and reject duplicate initialize calls.",
		Confirmed:   true,
		Evidence:    description,
	}
}

func initializeMessage(id int) (client.JSONRPCMessage, error) {
	params, err := json.Marshal(client.InitializeParams{
		ProtocolVersion: client.ProtocolVersion,
		Capabilities:    client.ClientCapabilities{},
		ClientInfo:      client.ClientInfo{Name: "MCPwn desync probe", Version: "1.0.0"},
	})
	if err != nil {
		return client.JSONRPCMessage{}, fmt.Errorf("desync initialize params failed: %w", err)
	}
	return client.JSONRPCMessage{JSONRPC: "2.0", ID: rawID(id), Method: "initialize", Params: params}, nil
}

func rawID(id int) json.RawMessage {
	return json.RawMessage(strconv.Itoa(id))
}

type readOutcome struct {
	msg client.JSONRPCMessage
	err error
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
		case <-time.After(readWindow):
			return client.JSONRPCMessage{}, true, errors.New("desync probe read timed out")
		}
	}
}
