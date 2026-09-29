package traversal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

type stubCaller struct {
	calls   int32
	respond func(call int, arguments json.RawMessage) (json.RawMessage, error)
}

func (s *stubCaller) CallTool(name string, arguments json.RawMessage) (json.RawMessage, error) {
	call := int(atomic.AddInt32(&s.calls, 1))
	return s.respond(call, arguments)
}

type probeArguments struct {
	Path string `json:"filePath"`
}

func textResponse(text string) (json.RawMessage, error) {
	return json.Marshal(probeResponse{Content: []probeContent{{Type: "text", Text: text}}})
}

func executingCaller() *stubCaller {
	return &stubCaller{respond: func(call int, arguments json.RawMessage) (json.RawMessage, error) {
		var args probeArguments
		if err := json.Unmarshal(arguments, &args); err != nil {
			return nil, err
		}
		cleaned := filepath.Clean(args.Path)
		data, err := os.ReadFile(cleaned)
		if err != nil {
			return textResponse("cannot read path")
		}
		return textResponse(string(data))
	}}
}

func sanitizingCaller() *stubCaller {
	return &stubCaller{respond: func(call int, arguments json.RawMessage) (json.RawMessage, error) {
		return textResponse("path rejected by security policy")
	}}
}

func slowCaller() *stubCaller {
	return &stubCaller{respond: func(call int, arguments json.RawMessage) (json.RawMessage, error) {
		time.Sleep(300 * time.Millisecond)
		return textResponse("late response")
	}}
}

func traversalFinding() auditor.Finding {
	return auditor.Finding{
		Severity:   auditor.SeverityHigh,
		RuleID:     "PathTraversal01",
		TargetTool: "readFileUnbounded",
		ParamPath:  "inputSchema.properties[filePath]",
	}
}

func TestConfirmFindingsExecutingServer(t *testing.T) {
	engine := NewEngine(executingCaller(), Options{})
	results := engine.ConfirmFindings([]auditor.Finding{traversalFinding()})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Confirmed {
		t.Fatal("expected confirmed traversal finding")
	}
	if !strings.Contains(results[0].Evidence, "mcpwn_traversal_") {
		t.Errorf("expected marker evidence, got %s", results[0].Evidence)
	}
}

func TestConfirmFindingsSanitizingServer(t *testing.T) {
	engine := NewEngine(sanitizingCaller(), Options{})
	results := engine.ConfirmFindings([]auditor.Finding{traversalFinding()})
	if results[0].Confirmed {
		t.Error("expected unconfirmed finding against sanitizing server")
	}
}

func TestConfirmFindingsTimeoutAborts(t *testing.T) {
	caller := slowCaller()
	engine := NewEngine(caller, Options{Timeout: 50 * time.Millisecond})
	results := engine.ConfirmFindings([]auditor.Finding{traversalFinding()})
	if results[0].Confirmed {
		t.Error("expected no confirmation on timeout")
	}
	if got := atomic.LoadInt32(&caller.calls); got != 1 {
		t.Errorf("expected engine to abort after first timeout, got %d calls", got)
	}
}

func TestConfirmFindingsIgnoresOtherRules(t *testing.T) {
	caller := executingCaller()
	engine := NewEngine(caller, Options{})
	other := auditor.Finding{RuleID: "CmdInjection01", TargetTool: "systemExec", ParamPath: "inputSchema.properties[cmd]"}
	results := engine.ConfirmFindings([]auditor.Finding{other})
	if results[0].Confirmed || results[0].RuleID != "CmdInjection01" {
		t.Error("expected non traversal finding untouched")
	}
	if got := atomic.LoadInt32(&caller.calls); got != 0 {
		t.Errorf("expected no calls for non traversal finding, got %d", got)
	}
}

func TestTraversalPayloadsShape(t *testing.T) {
	payloads := traversalPayloads("/tmp", "mcpwn_traversal_abc")
	if len(payloads) != 6 {
		t.Fatalf("expected 6 payloads, got %d", len(payloads))
	}
	if payloads[0] != "/tmp/mcpwn_traversal_abc" {
		t.Errorf("expected absolute payload first, got %s", payloads[0])
	}
	if !strings.Contains(payloads[1], "../../tmp/mcpwn_traversal_abc") {
		t.Errorf("expected relative payload, got %s", payloads[1])
	}
}
