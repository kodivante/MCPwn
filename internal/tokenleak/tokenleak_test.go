package tokenleak

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

type stubCaller struct {
	respond func(arguments json.RawMessage) (json.RawMessage, error)
}

func (s *stubCaller) CallTool(name string, arguments json.RawMessage) (json.RawMessage, error) {
	return s.respond(arguments)
}

func cleanCaller() *stubCaller {
	return &stubCaller{respond: func(arguments json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"content":[{"type":"text","text":"operation completed successfully"}],"isError":false}`), nil
	}}
}

func leakingCaller() *stubCaller {
	return &stubCaller{respond: func(arguments json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"content":[{"type":"text","text":"error: invalid api_key sk-proj-abc123xyz"}],"isError":true}`), nil
	}}
}

func errorLeakingCaller() *stubCaller {
	return &stubCaller{respond: func(arguments json.RawMessage) (json.RawMessage, error) {
		return nil, errWithSecret()
	}}
}

type secretError struct{}

func (secretError) Error() string {
	return "database error: connection refused using password=SuperSecret123"
}

func errWithSecret() error { return secretError{} }

func demoTool() toolInfo {
	return toolInfo{Name: "runQuery", Args: map[string]string{"query": "SELECT 1"}}
}

func TestProbeToolsCleanServer(t *testing.T) {
	engine := NewEngine(cleanCaller(), Options{})
	if findings := engine.ProbeTools([]toolInfo{demoTool()}); len(findings) != 0 {
		t.Errorf("expected 0 findings against clean server, got %d: %+v", len(findings), findings)
	}
}

func TestProbeToolsLeakingServer(t *testing.T) {
	engine := NewEngine(leakingCaller(), Options{})
	findings := engine.ProbeTools([]toolInfo{demoTool()})
	if len(findings) != 1 {
		t.Fatalf("expected 1 token leak finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].RuleID != "TokenLeak01" {
		t.Errorf("unexpected rule id %s", findings[0].RuleID)
	}
	if findings[0].Severity != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
	if !findings[0].Confirmed {
		t.Error("expected confirmed leak finding")
	}
	if !strings.Contains(findings[0].Evidence, "sk-") {
		t.Errorf("expected credential marker in evidence, got %s", findings[0].Evidence)
	}
}

func TestProbeToolsErrorLeak(t *testing.T) {
	engine := NewEngine(errorLeakingCaller(), Options{})
	findings := engine.ProbeTools([]toolInfo{demoTool()})
	if len(findings) != 1 {
		t.Fatalf("expected 1 error leak finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "password") {
		t.Errorf("expected password marker in evidence, got %s", findings[0].Evidence)
	}
}

func TestErrorLeakMarkers(t *testing.T) {
	tests := []struct {
		name     string
		errText  string
		wantFind bool
	}{
		{name: "bearer token", errText: "failed with Bearer abc123", wantFind: true},
		{name: "aws key", errText: "aws_secret_access_key leaked", wantFind: true},
		{name: "private key", errText: "-----BEGIN PRIVATE KEY", wantFind: true},
		{name: "jwt", errText: "token: jwt eyJhbGc", wantFind: true},
		{name: "clean error", errText: "connection timeout after 30s", wantFind: false},
		{name: "normal error", errText: "file not found: /tmp/data", wantFind: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, found := errorLeak(tc.errText, "test")
			if tc.wantFind && !found {
				t.Error("expected leak detection")
			}
			if !tc.wantFind && found {
				t.Error("unexpected leak detection")
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	long := strings.Repeat("a", 300)
	got := truncate(long, 200)
	if len(got) != 203 {
		t.Errorf("expected 203 chars, got %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Error("expected truncation suffix")
	}
}
