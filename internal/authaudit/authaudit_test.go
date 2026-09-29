package authaudit

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

func findingRule(findings []auditor.Finding, ruleID string) *auditor.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

func newOAuthServer(t *testing.T, metadataStatus int, metadataBody string, validateBearer bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="http://127.0.0.1:1/.well-known/oauth-authorization-server"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if validateBearer && r.Header.Get("Authorization") != "Bearer valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(metadataStatus)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, metadataBody)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestProbeMissingMetadata(t *testing.T) {
	server := newOAuthServer(t, http.StatusNotFound, `{}`, true)
	engine := NewEngine(server.URL+"/mcp", "", Options{})
	findings := engine.Probe()
	if findingRule(findings, "OAuthMetadata01") == nil {
		t.Errorf("expected missing metadata finding, got %+v", findings)
	}
}

func TestProbeWeakPkce(t *testing.T) {
	metadata := `{"authorization_endpoint":"https://idp.example.com/authorize","code_challenge_methods_supported":["plain"]}`
	server := newOAuthServer(t, http.StatusOK, metadata, true)
	engine := NewEngine(server.URL+"/mcp", "", Options{})
	findings := engine.Probe()
	if findingRule(findings, "OAuthMetadata01") != nil {
		t.Error("metadata exists and must not be flagged as missing")
	}
	pkce := findingRule(findings, "OAuthPkce01")
	if pkce == nil {
		t.Fatalf("expected pkce finding, got %+v", findings)
	}
	if pkce.Severity != auditor.SeverityMedium {
		t.Errorf("expected MEDIUM, got %s", pkce.Severity)
	}
}

func TestProbeStrongPkceClean(t *testing.T) {
	metadata := `{"authorization_endpoint":"https://idp.example.com/authorize","code_challenge_methods_supported":["S256","plain"]}`
	server := newOAuthServer(t, http.StatusOK, metadata, true)
	engine := NewEngine(server.URL+"/mcp", "", Options{})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected clean audit, got %+v", findings)
	}
}

func TestProbeTokenPassthrough(t *testing.T) {
	server := newOAuthServer(t, http.StatusOK, `{"code_challenge_methods_supported":["S256"]}`, false)
	engine := NewEngine(server.URL+"/mcp", "Bearer valid-token", Options{})
	findings := engine.Probe()
	passthrough := findingRule(findings, "TokenPassthrough01")
	if passthrough == nil {
		t.Fatalf("expected token passthrough finding, got %+v", findings)
	}
	if passthrough.Severity != auditor.SeverityHigh || !passthrough.Confirmed {
		t.Errorf("unexpected finding shape: %+v", *passthrough)
	}
}

func TestProbeSkipsServersWithoutAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer server.Close()
	engine := NewEngine(server.URL, "", Options{})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected no findings without 401 challenge, got %+v", findings)
	}
}
