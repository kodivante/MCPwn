package desync

import (
	"bufio"
	"encoding/json"
	"net"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/client"
	"github.com/kodivante/MCPwn/v3/internal/testutil"
)

const lenientToolsPayload = `{"tools":[{"name":"systemExec","inputSchema":{"type":"object","properties":{"cmd":{"type":"string"}}}}]}`

func lenientSource() TransportSource {
	return func() (client.Transport, error) {
		conn := testutil.Pipe(lenientToolsPayload)
		return client.NewStreamTransport(conn, conn), nil
	}
}

type strictRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
}

func strictResponse(id json.RawMessage, result string, rpcErr string) string {
	if rpcErr != "" {
		return `{"jsonrpc":"2.0","id":` + string(id) + `,"error":{"code":-32600,"message":"` + rpcErr + `"}}`
	}
	return `{"jsonrpc":"2.0","id":` + string(id) + `,"result":` + result + `}`
}

func serveStrict(conn net.Conn) error {
	defer conn.Close()
	initialized := false
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		var req strictRequest
		if json.Unmarshal(scanner.Bytes(), &req) != nil || len(req.ID) == 0 {
			continue
		}
		switch req.Method {
		case "initialize":
			if initialized {
				conn.Write([]byte(strictResponse(req.ID, "", "already initialized") + "\n"))
				continue
			}
			initialized = true
			conn.Write([]byte(strictResponse(req.ID, `{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"strict","version":"1.0"}}`, "") + "\n"))
		case "tools/list":
			if !initialized {
				conn.Write([]byte(strictResponse(req.ID, "", "server not initialized") + "\n"))
				continue
			}
			conn.Write([]byte(strictResponse(req.ID, `{"tools":[]}`, "") + "\n"))
		default:
			conn.Write([]byte(strictResponse(req.ID, "", "method not allowed") + "\n"))
		}
	}
	return scanner.Err()
}

func strictSource() TransportSource {
	return func() (client.Transport, error) {
		clientConn, serverConn := net.Pipe()
		go func() { _ = serveStrict(serverConn) }()
		return client.NewStreamTransport(clientConn, clientConn), nil
	}
}

func failingSource() TransportSource {
	return func() (client.Transport, error) {
		return nil, errSourceUnavailable()
	}
}

type sourceError struct{}

func (sourceError) Error() string { return "source unavailable" }

func errSourceUnavailable() error { return sourceError{} }

func TestProbeLenientServer(t *testing.T) {
	engine := NewEngine(lenientSource(), Options{})
	findings := engine.Probe()
	if len(findings) != 3 {
		t.Fatalf("expected 3 desync findings against lenient server, got %d", len(findings))
	}
	descriptions := make(map[string]bool)
	for _, finding := range findings {
		if finding.RuleID != "StateDesync01" {
			t.Errorf("unexpected rule id %s", finding.RuleID)
		}
		if finding.Severity != auditor.SeverityMedium {
			t.Errorf("expected MEDIUM severity, got %s", finding.Severity)
		}
		if !finding.Confirmed {
			t.Error("expected confirmed desync finding")
		}
		descriptions[finding.Description] = true
	}
	if len(descriptions) != 3 {
		t.Errorf("expected 3 distinct descriptions, got %v", descriptions)
	}
}

func TestProbeStrictServer(t *testing.T) {
	engine := NewEngine(strictSource(), Options{})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings against strict server, got %d: %+v", len(findings), findings)
	}
}

func TestProbeFailingSource(t *testing.T) {
	engine := NewEngine(failingSource(), Options{})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings on failing source, got %d", len(findings))
	}
}

func TestFindingShape(t *testing.T) {
	finding := desyncFinding("test description")
	if finding.TargetTool != "server" || finding.ParamPath != "lifecycle" {
		t.Errorf("unexpected finding shape: %+v", finding)
	}
	if finding.Evidence != "test description" {
		t.Errorf("expected evidence to mirror description, got %s", finding.Evidence)
	}
}
