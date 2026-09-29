package serverrequest

import (
	"bufio"
	"encoding/json"
	"net"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/client"
	"github.com/kodivante/MCPwn/v3/internal/testutil"
)

type probeRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
}

func serveAcceptingServerRequests(conn net.Conn) error {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		var req probeRequest
		if json.Unmarshal(scanner.Bytes(), &req) != nil || len(req.ID) == 0 {
			continue
		}
		switch req.Method {
		case "initialize":
			conn.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"probe","version":"1.0"}}}` + "\n"))
		case "elicitation/create":
			conn.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":{"action":"accept","content":{"type":"text","text":"confirmed"}}}` + "\n"))
		case "roots/list":
			conn.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":{"roots":[{"uri":"file:///home","name":"home"}]}}` + "\n"))
		default:
			conn.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":{"tools":[]}}` + "\n"))
		}
	}
	return scanner.Err()
}

func acceptingSource() TransportSource {
	return func() (client.Transport, error) {
		clientConn, serverConn := net.Pipe()
		go func() { _ = serveAcceptingServerRequests(serverConn) }()
		return client.NewStreamTransport(clientConn, clientConn), nil
	}
}

func rejectingSource() TransportSource {
	return func() (client.Transport, error) {
		conn := testutil.Pipe(`{"tools":[]}`)
		return client.NewStreamTransport(conn, conn), nil
	}
}

func TestProbeElicitationAcceptingServer(t *testing.T) {
	engine := NewEngine(acceptingSource(), Options{})
	findings := engine.ProbeElicitation()
	if len(findings) != 1 {
		t.Fatalf("expected 1 elicitation finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].RuleID != "ElicitationAbuse01" {
		t.Errorf("unexpected rule id %s", findings[0].RuleID)
	}
	if findings[0].Severity != auditor.SeverityMedium {
		t.Errorf("expected MEDIUM severity, got %s", findings[0].Severity)
	}
	if !findings[0].Confirmed {
		t.Error("expected confirmed finding")
	}
}

func TestProbeElicitationRejectingServer(t *testing.T) {
	engine := NewEngine(rejectingSource(), Options{})
	if findings := engine.ProbeElicitation(); len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestProbeRootsAcceptingServer(t *testing.T) {
	engine := NewEngine(acceptingSource(), Options{})
	findings := engine.ProbeRoots()
	if len(findings) != 1 {
		t.Fatalf("expected 1 roots finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].RuleID != "RootsProbe01" {
		t.Errorf("unexpected rule id %s", findings[0].RuleID)
	}
}

func TestProbeRootsRejectingServer(t *testing.T) {
	engine := NewEngine(rejectingSource(), Options{})
	if findings := engine.ProbeRoots(); len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestProbeFailingSource(t *testing.T) {
	engine := NewEngine(func() (client.Transport, error) {
		return nil, errSourceUnavailable{}
	}, Options{})
	if findings := engine.ProbeElicitation(); len(findings) != 0 {
		t.Errorf("expected 0 findings on failing source, got %d", len(findings))
	}
	if findings := engine.ProbeRoots(); len(findings) != 0 {
		t.Errorf("expected 0 roots findings on failing source, got %d", len(findings))
	}
}

type errSourceUnavailable struct{}

func (errSourceUnavailable) Error() string { return "source unavailable" }
