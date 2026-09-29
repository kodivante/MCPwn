package raceprober

import (
	"bufio"
	"encoding/json"
	"net"
	"sync/atomic"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/client"
	"github.com/kodivante/MCPwn/v3/internal/schema"
	"github.com/kodivante/MCPwn/v3/internal/testutil"
)

const toolsPayload = `{"tools":[{"name":"systemExec","inputSchema":{"type":"object","properties":{"cmd":{"type":"string"}}}}]}`

func consistentSource() TransportSource {
	return func() (client.Transport, error) {
		conn := testutil.Pipe(toolsPayload)
		return client.NewStreamTransport(conn, conn), nil
	}
}

func flakySource(state *int32) TransportSource {
	return func() (client.Transport, error) {
		clientConn, serverConn := net.Pipe()
		go func() {
			_ = serveFlaky(serverConn, state)
		}()
		return client.NewStreamTransport(clientConn, clientConn), nil
	}
}

type flakyRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
}

func serveFlaky(conn net.Conn, state *int32) error {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		var req flakyRequest
		if json.Unmarshal(scanner.Bytes(), &req) != nil || len(req.ID) == 0 {
			continue
		}
		switch req.Method {
		case "initialize":
			writeFlaky(conn, req.ID, `{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"flaky","version":"1.0"}}`, "")
		case "tools/call":
			if atomic.AddInt32(state, 1)%2 == 0 {
				writeFlaky(conn, req.ID, "", "concurrent write conflict")
				continue
			}
			writeFlaky(conn, req.ID, `{"content":[{"type":"text","text":"ok"}],"isError":false}`, "")
		default:
			writeFlaky(conn, req.ID, "", "unsupported method")
		}
	}
	return scanner.Err()
}

func writeFlaky(conn net.Conn, id json.RawMessage, result, rpcErr string) {
	var line string
	if rpcErr != "" {
		line = `{"jsonrpc":"2.0","id":` + string(id) + `,"error":{"code":-32000,"message":"` + rpcErr + `"}}`
	} else {
		line = `{"jsonrpc":"2.0","id":` + string(id) + `,"result":` + result + `}`
	}
	conn.Write([]byte(line + "\n"))
}

func demoTools() []schema.Tool {
	return []schema.Tool{
		{
			Name: "systemExec",
			InputSchema: schema.JSONSchema{
				Type:       "object",
				Properties: map[string]schema.JSONSchema{"cmd": {Type: "string"}},
			},
		},
	}
}

func numericTools() []schema.Tool {
	return []schema.Tool{
		{
			Name: "calcTool",
			InputSchema: schema.JSONSchema{
				Type:       "object",
				Properties: map[string]schema.JSONSchema{"value": {Type: "number"}},
			},
		},
	}
}

func TestProbeConsistentServer(t *testing.T) {
	engine := NewEngine(consistentSource(), demoTools(), Options{})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings against consistent server, got %d: %+v", len(findings), findings)
	}
}

func TestProbeFlakyServer(t *testing.T) {
	var state int32
	engine := NewEngine(flakySource(&state), demoTools(), Options{})
	findings := engine.Probe()
	if len(findings) != 1 {
		t.Fatalf("expected 1 race finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].RuleID != "RaceCondition01" {
		t.Errorf("unexpected rule id %s", findings[0].RuleID)
	}
	if findings[0].Severity != auditor.SeverityMedium {
		t.Errorf("expected MEDIUM severity, got %s", findings[0].Severity)
	}
	if !findings[0].Confirmed {
		t.Error("expected confirmed race finding")
	}
}

func TestProbeSkipsToolsWithoutStringParams(t *testing.T) {
	engine := NewEngine(consistentSource(), numericTools(), Options{})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings for tools without string params, got %d", len(findings))
	}
}
