package httpthreat

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

func newVulnerableServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Mcp-Session-Id", "sess-1")
		w.Header().Set("Content-Type", "application/json")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32700,"message":"parse"}}`)
			return
		}
		if len(body) > 0 && body[0] == '[' {
			fmt.Fprint(w, `[{"jsonrpc":"2.0","id":9,"result":{"tools":[]}}]`)
			return
		}
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"vulnerable","version":"1.0"}}}`)
	}))
	t.Cleanup(server.Close)
	return server
}

func newHardenedServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		if r.Header.Get("Origin") != "" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"forbidden origin"}`)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(body) > 0 && body[0] == '[' {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"batch not allowed"}`)
			return
		}
		if r.Header.Get("Mcp-Session-Id") == "mcpwn-invalid-session" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"unknown session"}`)
			return
		}
		w.Header().Set("Mcp-Session-Id", "sess-1")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"hardened","version":"1.0"}}}`)
	}))
	t.Cleanup(server.Close)
	return server
}

func findingByRule(findings []auditor.Finding, ruleID string) *auditor.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

func TestProbeVulnerableServer(t *testing.T) {
	server := newVulnerableServer(t)
	engine := NewEngine(server.URL, Options{})
	findings := engine.Probe()
	expected := []string{"HttpAuthBypass01", "HttpSession01", "HttpOrigin01", "HttpBatch01"}
	if len(findings) != len(expected) {
		t.Fatalf("expected %d findings, got %d: %+v", len(expected), len(findings), findings)
	}
	for _, ruleID := range expected {
		if findingByRule(findings, ruleID) == nil {
			t.Errorf("missing finding %s", ruleID)
		}
	}
	if findingByRule(findings, "HttpAuthBypass01").Severity != auditor.SeverityMedium {
		t.Error("expected MEDIUM auth bypass without configured auth")
	}
}

func TestProbeVulnerableServerWithAuthConfigured(t *testing.T) {
	server := newVulnerableServer(t)
	engine := NewEngine(server.URL, Options{AuthHeader: "Bearer token"})
	findings := engine.Probe()
	finding := findingByRule(findings, "HttpAuthBypass01")
	if finding == nil {
		t.Fatal("expected auth bypass finding")
	}
	if finding.Severity != auditor.SeverityHigh {
		t.Errorf("expected HIGH severity with configured auth, got %s", finding.Severity)
	}
}

func TestProbeHardenedServer(t *testing.T) {
	server := newHardenedServer(t)
	engine := NewEngine(server.URL, Options{AuthHeader: "Bearer token"})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings against hardened server, got %d: %+v", len(findings), findings)
	}
}

func TestProbeUnreachableServer(t *testing.T) {
	engine := NewEngine("http://127.0.0.1:1/mcp", Options{Timeout: 100000000})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings against unreachable server, got %d", len(findings))
	}
}
