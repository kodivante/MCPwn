package ssrfcanary

import (
	"encoding/json"
	"io"
	"net/http"
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

type probeArguments struct {
	Url string `json:"url"`
}

type probeContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type probeResponse struct {
	Content []probeContent `json:"content"`
	IsError bool           `json:"isError"`
}

func textResponse(text string) (json.RawMessage, error) {
	return json.Marshal(probeResponse{Content: []probeContent{{Type: "text", Text: text}}})
}

func fetchingCaller() *stubCaller {
	return &stubCaller{respond: func(arguments json.RawMessage) (json.RawMessage, error) {
		var args probeArguments
		if err := json.Unmarshal(arguments, &args); err != nil {
			return nil, err
		}
		resp, err := http.Get(args.Url)
		if err != nil {
			return textResponse("fetch failed")
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return textResponse("read failed")
		}
		return textResponse("fetched: " + string(data))
	}}
}

func ignoringCaller() *stubCaller {
	return &stubCaller{respond: func(arguments json.RawMessage) (json.RawMessage, error) {
		return textResponse("url recorded for later processing")
	}}
}

func ssrfFinding() auditor.Finding {
	return auditor.Finding{
		Severity:   auditor.SeverityMedium,
		RuleID:     "Ssrf01",
		TargetTool: "fetchUrl",
		ParamPath:  "inputSchema.properties[url]",
	}
}

func TestConfirmFindingsFetchingServer(t *testing.T) {
	engine := NewEngine(fetchingCaller(), Options{})
	results := engine.ConfirmFindings([]auditor.Finding{ssrfFinding()})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Confirmed {
		t.Fatal("expected confirmed ssrf finding")
	}
	if !strings.Contains(results[0].Evidence, "canary") {
		t.Errorf("expected canary evidence, got %s", results[0].Evidence)
	}
	if !strings.Contains(results[0].Evidence, "127.0.0.1") {
		t.Errorf("expected local canary url in evidence, got %s", results[0].Evidence)
	}
}

func TestConfirmFindingsIgnoringServer(t *testing.T) {
	engine := NewEngine(ignoringCaller(), Options{})
	results := engine.ConfirmFindings([]auditor.Finding{ssrfFinding()})
	if results[0].Confirmed {
		t.Error("expected unconfirmed finding against server that ignores urls")
	}
}

func TestConfirmFindingsNoSsrfTargets(t *testing.T) {
	caller := fetchingCaller()
	engine := NewEngine(caller, Options{})
	other := auditor.Finding{RuleID: "CmdInjection01", TargetTool: "systemExec", ParamPath: "inputSchema.properties[cmd]"}
	results := engine.ConfirmFindings([]auditor.Finding{other})
	if results[0].RuleID != "CmdInjection01" || results[0].Confirmed {
		t.Error("expected non ssrf finding untouched")
	}
}

func TestCanaryStartStop(t *testing.T) {
	canary, err := startCanary()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(canary.url, "127.0.0.1") {
		t.Errorf("expected local canary url, got %s", canary.url)
	}
	if canary.wasHit() {
		t.Error("expected canary to start unhit")
	}
	if err := canary.stop(); err != nil {
		t.Fatalf("unexpected stop error: %v", err)
	}
}
