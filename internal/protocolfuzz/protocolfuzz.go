package protocolfuzz

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/client"
)

const (
	defaultTimeout  = 10 * time.Second
	defaultReadWait = 3 * time.Second
	livenessID      = 100
)

const garbageInitializeParams = `{"protocolVersion":"999.999.999","capabilities":{},"clientInfo":{"name":"MCPwn probe","version":"1.0.0"}}`

type TransportSource func() (client.Transport, error)

type Options struct {
	Timeout  time.Duration
	ReadWait time.Duration
}

type Engine struct {
	source   TransportSource
	readWait time.Duration
}

type malformedProbe struct {
	name    string
	message client.JSONRPCMessage
}

func NewEngine(source TransportSource, options Options) *Engine {
	readWait := options.ReadWait
	if readWait <= 0 {
		readWait = defaultReadWait
	}
	return &Engine{source: source, readWait: readWait}
}

func (e *Engine) Probe() []auditor.Finding {
	var findings []auditor.Finding
	for _, probe := range malformedProbes() {
		if finding, ok := e.runProbe(probe); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func malformedProbes() []malformedProbe {
	return []malformedProbe{
		{name: "missing jsonrpc version", message: client.JSONRPCMessage{ID: rawID(1), Method: "tools/list"}},
		{name: "wrong jsonrpc version", message: client.JSONRPCMessage{JSONRPC: "1.0", ID: rawID(1), Method: "tools/list"}},
		{name: "invalid id type", message: client.JSONRPCMessage{JSONRPC: "2.0", ID: json.RawMessage(`{"nested":true}`), Method: "tools/list"}},
		{name: "unknown method", message: client.JSONRPCMessage{JSONRPC: "2.0", ID: rawID(1), Method: "mcpwn/probe"}},
		{name: "wrong params type", message: client.JSONRPCMessage{JSONRPC: "2.0", ID: rawID(1), Method: "tools/list", Params: json.RawMessage(`"notAnObject"`)}},
		{name: "unsupported protocol version", message: client.JSONRPCMessage{JSONRPC: "2.0", ID: rawID(1), Method: "initialize", Params: json.RawMessage(garbageInitializeParams)}},
	}
}

func (e *Engine) runProbe(probe malformedProbe) (auditor.Finding, bool) {
	transport, err := e.source()
	if err != nil {
		return auditor.Finding{}, false
	}
	defer transport.Close()

	if err := transport.Send(probe.message); err != nil {
		return robustnessFinding("HIGH", probe.name, "server dropped the connection while receiving the malformed message"), true
	}

	sendDone := make(chan error, 1)
	go func() {
		sendDone <- transport.Send(livenessMessage())
	}()

	_, timedOut, err := e.awaitResponse(transport, livenessID)
	if timedOut {
		select {
		case sendErr := <-sendDone:
			if sendErr != nil {
				return robustnessFinding("HIGH", probe.name, "server dropped the connection after the malformed message"), true
			}
		default:
		}
		return robustnessFinding("MEDIUM", probe.name, "server stopped responding after the malformed message"), true
	}
	if err != nil {
		return robustnessFinding("HIGH", probe.name, "server connection failed after the malformed message"), true
	}
	return auditor.Finding{}, false
}

func livenessMessage() client.JSONRPCMessage {
	return client.JSONRPCMessage{JSONRPC: "2.0", ID: rawID(livenessID), Method: "tools/list"}
}

func robustnessFinding(severity, probe, evidence string) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.Severity(severity),
		RuleID:      "ProtocolRobustness01",
		TargetTool:  "server",
		ParamPath:   "protocol",
		Description: "Server mishandled malformed JSON-RPC input: " + probe,
		Remediation: "Validate every JSON-RPC message and answer with protocol errors instead of dropping the connection or crashing.",
		Confirmed:   true,
		Evidence:    evidence + " (probe: " + probe + ")",
	}
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
		case <-time.After(e.readWait):
			return client.JSONRPCMessage{}, true, errors.New("protocol probe read timed out")
		}
	}
}
