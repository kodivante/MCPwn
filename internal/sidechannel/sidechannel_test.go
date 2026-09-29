package sidechannel

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

type stubCaller struct {
	respond func(arguments json.RawMessage) (json.RawMessage, error)
}

func (s *stubCaller) CallTool(name string, arguments json.RawMessage) (json.RawMessage, error) {
	return s.respond(arguments)
}

func stringTool() schema.Tool {
	return schema.Tool{
		Name: "executeQuery",
		InputSchema: schema.JSONSchema{
			Type: "object",
			Properties: map[string]schema.JSONSchema{
				"query": {Type: "string"},
			},
			Required: []string{"query"},
		},
	}
}

func argsValue(arguments json.RawMessage) string {
	var values map[string]string
	if err := json.Unmarshal(arguments, &values); err != nil {
		return ""
	}
	return values["query"]
}

func TestProbeFastServer(t *testing.T) {
	caller := &stubCaller{respond: func(arguments json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"content":[{"type":"text","text":"done"}]}`), nil
	}}
	engine := NewEngine(caller, []schema.Tool{stringTool()}, Options{})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings against fast server, got %d", len(findings))
	}
}

func TestProbeTimingSideChannel(t *testing.T) {
	caller := &stubCaller{respond: func(arguments json.RawMessage) (json.RawMessage, error) {
		if strings.Contains(argsValue(arguments), "sleep") {
			time.Sleep(300 * time.Millisecond)
		}
		return json.RawMessage(`{"content":[{"type":"text","text":"done"}]}`), nil
	}}
	engine := NewEngine(caller, []schema.Tool{stringTool()}, Options{})
	findings := engine.Probe()
	if len(findings) == 0 {
		t.Fatal("expected timing side-channel finding, got 0")
	}
	if findings[0].RuleID != "SideChannel01" {
		t.Errorf("expected SideChannel01, got %s", findings[0].RuleID)
	}
	if findings[0].Confirmed {
		t.Error("side-channel findings must not be marked confirmed")
	}
}

func TestProbeSizeSideChannel(t *testing.T) {
	caller := &stubCaller{respond: func(arguments json.RawMessage) (json.RawMessage, error) {
		if strings.Contains(argsValue(arguments), "sleep") {
			return json.RawMessage(`{"content":[{"type":"text","text":"` + strings.Repeat("leak", 40) + `"}]}`), nil
		}
		return json.RawMessage(`{"content":[{"type":"text","text":"done"}]}`), nil
	}}
	engine := NewEngine(caller, []schema.Tool{stringTool()}, Options{})
	findings := engine.Probe()
	found := false
	for _, finding := range findings {
		if finding.RuleID == "SideChannel03" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SideChannel03 size finding, got %d findings", len(findings))
	}
}

func TestProbeNoStringArgs(t *testing.T) {
	tool := schema.Tool{
		Name: "countOnly",
		InputSchema: schema.JSONSchema{
			Type: "object",
			Properties: map[string]schema.JSONSchema{
				"count": {Type: "integer"},
			},
		},
	}
	engine := NewEngine(&stubCaller{}, []schema.Tool{tool}, Options{})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings without string args, got %d", len(findings))
	}
}

func TestTimingThreshold(t *testing.T) {
	base := 50 * time.Millisecond
	threshold := timingThreshold(base)
	if threshold != timingFloor {
		t.Errorf("expected floor %s for small baseline, got %s", timingFloor, threshold)
	}
	slowBase := time.Second
	slowThreshold := timingThreshold(slowBase)
	if slowThreshold != 3*time.Second {
		t.Errorf("expected 3s for 1s baseline, got %s", slowThreshold)
	}
}

func TestProbeSizeDiff(t *testing.T) {
	baseline := probeSample{raw: make([]byte, 100)}
	probe := probeSample{raw: make([]byte, 500)}
	if !probeSizeDiff(baseline, probe) {
		t.Error("expected size diff detection for 5x growth")
	}
	similar := probeSample{raw: make([]byte, 120)}
	if probeSizeDiff(baseline, similar) {
		t.Error("unexpected size diff for 1.2x growth")
	}
}

func TestSeverityLevels(t *testing.T) {
	timing := timingFinding(stringTool(), probeSample{latency: time.Second}, probeSample{latency: 3 * time.Second})
	if timing.Severity != auditor.SeverityMedium {
		t.Errorf("expected MEDIUM for timing, got %s", timing.Severity)
	}
	size := sizeDiffFinding(stringTool(), probeSample{raw: []byte("aa")}, probeSample{raw: []byte("aaaa")})
	if size.Severity != auditor.SeverityLow {
		t.Errorf("expected LOW for size, got %s", size.Severity)
	}
}
