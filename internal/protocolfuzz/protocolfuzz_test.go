package protocolfuzz

import (
	"bufio"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/client"
	"github.com/kodivante/MCPwn/v3/internal/testutil"
)

const toolsPayload = `{"tools":[{"name":"systemExec","inputSchema":{"type":"object","properties":{"cmd":{"type":"string"}}}}]}`

func resilientSource() TransportSource {
	return func() (client.Transport, error) {
		conn := testutil.Pipe(toolsPayload)
		return client.NewStreamTransport(conn, conn), nil
	}
}

type fragileRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
}

func serveFragile(conn net.Conn) error {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if containsMalformed(line) {
			return nil
		}
		var req fragileRequest
		if json.Unmarshal([]byte(line), &req) != nil || len(req.ID) == 0 {
			continue
		}
		response := `{"jsonrpc":"2.0","id":` + string(req.ID) + `,"error":{"code":-32600,"message":"rejected"}}`
		conn.Write([]byte(response + "\n"))
	}
	return scanner.Err()
}

func containsMalformed(line string) bool {
	return len(line) > 0 && (contains(line, "mcpwn/probe") || contains(line, `"1.0"`) || !contains(line, "jsonrpc"))
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func fragileSource() TransportSource {
	return func() (client.Transport, error) {
		clientConn, serverConn := net.Pipe()
		go func() {
			_ = serveFragile(serverConn)
		}()
		return client.NewStreamTransport(clientConn, clientConn), nil
	}
}

func silentSource() TransportSource {
	return func() (client.Transport, error) {
		clientConn, serverConn := net.Pipe()
		go func() {
			_ = serveSilent(serverConn)
		}()
		return client.NewStreamTransport(clientConn, clientConn), nil
	}
}

func serveSilent(conn net.Conn) error {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
	}
	return scanner.Err()
}

func TestProbeResilientServer(t *testing.T) {
	engine := NewEngine(resilientSource(), Options{})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings against resilient server, got %d: %+v", len(findings), findings)
	}
}

func TestProbeFragileServer(t *testing.T) {
	engine := NewEngine(fragileSource(), Options{ReadWait: 2 * time.Second})
	findings := engine.Probe()
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings against fragile server, got %d: %+v", len(findings), findings)
	}
	for _, finding := range findings {
		if finding.RuleID != "ProtocolRobustness01" {
			t.Errorf("unexpected rule id %s", finding.RuleID)
		}
		if finding.Severity != auditor.SeverityHigh {
			t.Errorf("expected HIGH severity for dropped connection, got %s", finding.Severity)
		}
		if !finding.Confirmed {
			t.Error("expected confirmed robustness finding")
		}
	}
}

func TestProbeSilentServer(t *testing.T) {
	engine := NewEngine(silentSource(), Options{ReadWait: 100 * time.Millisecond})
	findings := engine.Probe()
	if len(findings) != 6 {
		t.Fatalf("expected 6 findings against silent server, got %d", len(findings))
	}
	for _, finding := range findings {
		if finding.Severity != auditor.SeverityMedium {
			t.Errorf("expected MEDIUM severity for silent server, got %s", finding.Severity)
		}
	}
}

func TestProbeFailingSource(t *testing.T) {
	engine := NewEngine(func() (client.Transport, error) {
		return nil, errSource()
	}, Options{})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings on failing source, got %d", len(findings))
	}
}

type sourceError struct{}

func (sourceError) Error() string { return "source unavailable" }

func errSource() error { return sourceError{} }
