package serverrequest

import (
	"encoding/json"
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

type probeSpec struct {
	method      string
	params      json.RawMessage
	ruleID      string
	path        string
	description string
	remediation string
}

func NewEngine(source TransportSource, options Options) *Engine {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Engine{source: source, timeout: timeout}
}

func (e *Engine) ProbeElicitation() []auditor.Finding {
	return e.probeMethod(probeSpec{
		method:      "elicitation/create",
		params:      json.RawMessage(`{"message":"Confirm this action","requestedSchema":{"type":"string"}}`),
		ruleID:      "ElicitationAbuse01",
		path:        "elicitation",
		description: "Server accepts elicitation/create requests, enabling it to solicit user input and credentials through the client UI",
		remediation: "Restrict elicitation handling server-side. A malicious MCP server with elicitation access can phish users through fake confirmation dialogs.",
	})
}

func (e *Engine) ProbeRoots() []auditor.Finding {
	return e.probeMethod(probeSpec{
		method:      "roots/list",
		ruleID:      "RootsProbe01",
		path:        "roots",
		description: "Server accepts roots/list requests, exposing client filesystem root enumeration capability",
		remediation: "Restrict roots handling server-side. A malicious server can map the client filesystem scope through root enumeration.",
	})
}

func (e *Engine) probeMethod(spec probeSpec) []auditor.Finding {
	transport, err := e.source()
	if err != nil {
		return nil
	}
	defer transport.Close()
	if err := handshake(transport); err != nil {
		return nil
	}
	request := client.JSONRPCMessage{JSONRPC: "2.0", ID: rawID(1), Method: spec.method, Params: spec.params}
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- transport.Send(request)
	}()
	response, timedOut, err := e.awaitResponse(transport, 1)
	if timedOut {
		select {
		case sendErr := <-sendDone:
			if sendErr != nil {
				return nil
			}
		default:
		}
		return nil
	}
	if err != nil {
		return nil
	}
	if response.Error != nil || response.Result == nil {
		return nil
	}
	return []auditor.Finding{{
		Severity:    auditor.SeverityMedium,
		RuleID:      spec.ruleID,
		TargetTool:  "server",
		ParamPath:   spec.path,
		Description: spec.description,
		Remediation: spec.remediation,
		Confirmed:   true,
		Evidence:    fmt.Sprintf("%s returned success (response: %q)", spec.method, truncate(string(response.Result), 200)),
	}}
}

func handshake(transport client.Transport) error {
	initializeParams := json.RawMessage(`{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"MCPwn server request probe","version":"1.0.0"}}`)
	message := client.JSONRPCMessage{JSONRPC: "2.0", ID: rawID(0), Method: "initialize", Params: initializeParams}
	if err := transport.Send(message); err != nil {
		return fmt.Errorf("probe handshake failed: %w", err)
	}
	if _, timedOut, err := awaitInitResponse(transport); timedOut || err != nil {
		return fmt.Errorf("probe handshake response failed: %w", err)
	}
	initialized := client.JSONRPCMessage{JSONRPC: "2.0", Method: "notifications/initialized"}
	return transport.Send(initialized)
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
		if string(res.msg.ID) != "0" {
			return awaitInitResponse(transport)
		}
		return res.msg, false, nil
	case <-time.After(readWindow):
		return client.JSONRPCMessage{}, true, fmt.Errorf("handshake response timed out")
	}
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
			return client.JSONRPCMessage{}, true, fmt.Errorf("probe timed out")
		}
	}
}

func truncate(text string, max int) string {
	if len(text) <= max {
		return text
	}
	return text[:max] + "..."
}

func rawID(id int) json.RawMessage {
	return json.RawMessage(strconv.Itoa(id))
}
