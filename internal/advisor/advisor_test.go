package advisor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/capability"
)

func TestConsultReturnsAdvisoryHints(t *testing.T) {
	profiles := []capability.ToolCapability{
		{Tool: "systemExec", Capabilities: []string{capability.Exec}},
		{Tool: "loginUser", Capabilities: []string{capability.Credentials}},
	}
	execHash := toolHash("systemExec")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request advisoryRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(request.Findings) == 0 || len(request.Tools) == 0 {
			t.Errorf("expected anonymized findings and tools, got %+v", request)
		}
		for _, tool := range request.Tools {
			if tool.Hash == "" || len(tool.Capabilities) == 0 {
				t.Errorf("expected hash and capabilities per tool, got %+v", tool)
			}
		}
		for _, finding := range request.Findings {
			if finding.Rule == "" || finding.ToolHash == "" {
				t.Errorf("expected rule and hash per finding, got %+v", finding)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt := `{"hypotheses":[{"toolHash":"` + execHash + `","probe":"try sleep-based timing","note":"exec capability with string param"}]}`
		w.Write([]byte(fmt))
	}))
	defer server.Close()

	engine := NewEngine(Options{Endpoint: server.URL})
	findings := []auditor.Finding{{RuleID: "CmdInjection01", TargetTool: "systemExec", Severity: auditor.SeverityCritical}}
	hints, err := engine.Consult(findings, profiles)
	if err != nil {
		t.Fatalf("consult failed: %v", err)
	}
	if len(hints) != 1 {
		t.Fatalf("expected 1 hint, got %+v", hints)
	}
	if hints[0].RuleID != "AdvisorHint01" || hints[0].TargetTool != "systemExec" {
		t.Errorf("unexpected hint: %+v", hints[0])
	}
	if hints[0].Severity != auditor.SeverityLow || hints[0].Confirmed {
		t.Error("hints must be LOW severity and never confirmed")
	}
	if hints[0].Confidence != 40 {
		t.Errorf("expected capped confidence 40, got %d", hints[0].Confidence)
	}
}

func TestConsultSkipsUnknownToolHashes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hypotheses":[{"toolHash":"deadbeef1234","probe":"x","note":"y"}]}`))
	}))
	defer server.Close()
	engine := NewEngine(Options{Endpoint: server.URL})
	hints, err := engine.Consult(nil, []capability.ToolCapability{{Tool: "real"}})
	if err != nil {
		t.Fatalf("consult failed: %v", err)
	}
	if len(hints) != 0 {
		t.Errorf("expected hints for known tools only, got %+v", hints)
	}
}

func TestConsultCapsHintCount(t *testing.T) {
	profiles := []capability.ToolCapability{{Tool: "tool"}}
	hash := toolHash("tool")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := `{"hypotheses":[`
		for i := 0; i < 20; i++ {
			if i > 0 {
				response += ","
			}
			response += `{"toolHash":"` + hash + `","probe":"p` + string(rune('a'+i)) + `","note":"n"}`
		}
		response += `]}`
		w.Write([]byte(response))
	}))
	defer server.Close()
	engine := NewEngine(Options{Endpoint: server.URL})
	hints, err := engine.Consult(nil, profiles)
	if err != nil {
		t.Fatalf("consult failed: %v", err)
	}
	if len(hints) != maxHints {
		t.Errorf("expected %d hints, got %d", maxHints, len(hints))
	}
}

func TestConsultDisabledEngine(t *testing.T) {
	engine := NewEngine(Options{})
	if hints, err := engine.Consult(nil, nil); hints != nil || err != nil {
		t.Errorf("expected no-op without endpoint, got %+v err=%v", hints, err)
	}
}

func TestConsultUnreachableServer(t *testing.T) {
	engine := NewEngine(Options{Endpoint: "http://127.0.0.1:1", Timeout: 100000000})
	if _, err := engine.Consult(nil, nil); err == nil {
		t.Error("expected error on unreachable advisor")
	}
}
