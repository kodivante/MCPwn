package restraversal

import (
	"strings"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/client"
	"github.com/kodivante/MCPwn/v3/internal/testutil"
)

func TestProbeVulnerableResourceServer(t *testing.T) {
	conn := testutil.PipeResourceReflecting()
	transport := client.NewStreamTransport(conn, conn)
	session := client.NewSession(transport)
	if err := session.Initialize(); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	engine := NewEngine(session, Options{})
	findings := engine.Probe()
	if len(findings) == 0 {
		t.Fatal("expected resource traversal finding against reflecting server, got 0")
	}
	if findings[0].RuleID != "ResourceTraversal01" {
		t.Errorf("unexpected rule id %s", findings[0].RuleID)
	}
	if findings[0].Severity != auditor.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
	if !findings[0].Confirmed {
		t.Error("expected confirmed finding")
	}
	if !strings.Contains(findings[0].Evidence, "marker") {
		t.Errorf("expected marker in evidence, got %s", findings[0].Evidence)
	}
}

func TestProbeSafeResourceServer(t *testing.T) {
	conn := testutil.PipeResourceSafe()
	transport := client.NewStreamTransport(conn, conn)
	session := client.NewSession(transport)
	if err := session.Initialize(); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	engine := NewEngine(session, Options{})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings against safe server, got %d: %+v", len(findings), findings)
	}
}

func TestBuildProbeURI(t *testing.T) {
	tests := []struct {
		name     string
		template string
		payload  string
		want     string
	}{
		{name: "absolute path", template: "file:///workspace/data.txt", payload: "/tmp/x.txt", want: "/tmp/x.txt"},
		{name: "file uri payload", template: "file:///workspace/data.txt", payload: "file:///tmp/x.txt", want: "file:///tmp/x.txt"},
		{name: "relative payload", template: "file:///workspace/data.txt", payload: "../x.txt", want: "file:///workspace/../x.txt"},
		{name: "no slash template", template: "data", payload: "../x.txt", want: "../x.txt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildProbeURI(tc.template, tc.payload)
			if got != tc.want {
				t.Errorf("buildProbeURI(%q, %q) = %q, want %q", tc.template, tc.payload, got, tc.want)
			}
		})
	}
}
