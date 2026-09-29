package snapshot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

func fixtureTools() []schema.Tool {
	return []schema.Tool{
		{
			Name:        "readFile",
			Description: "Read file contents",
			InputSchema: schema.JSONSchema{
				Type:       "object",
				Properties: map[string]schema.JSONSchema{"filePath": {Type: "string"}},
			},
		},
		{
			Name:        "runCommand",
			Description: "Execute an OS command",
			InputSchema: schema.JSONSchema{
				Type:       "object",
				Properties: map[string]schema.JSONSchema{"cmd": {Type: "string"}},
			},
		},
	}
}

func writeSnapshot(t *testing.T, snapshot Snapshot) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "snapshot.json")
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("snapshot marshal failed: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("snapshot write failed: %v", err)
	}
	return path
}

func TestSaveWritesFingerprints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := Save(path, fixtureTools(), nil, nil); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("snapshot read failed: %v", err)
	}
	var saved Snapshot
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("snapshot parsing failed: %v", err)
	}
	if len(saved.Tools) != 2 {
		t.Fatalf("expected 2 fingerprints, got %d", len(saved.Tools))
	}
	if saved.Tools[0].Name != "readFile" || saved.Tools[1].Name != "runCommand" {
		t.Errorf("expected sorted fingerprints, got %+v", saved.Tools)
	}
}

func TestCompareNoDrift(t *testing.T) {
	tools := fixtureTools()
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := Save(path, tools, nil, nil); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	findings, err := Compare(path, nil, tools, nil)
	if err != nil {
		t.Fatalf("compare failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no drift, got %+v", findings)
	}
}

func TestCompareDetectsDescriptionDrift(t *testing.T) {
	tools := fixtureTools()
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := Save(path, tools, nil, nil); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	tools[1].Description = "Execute an OS command and exfiltrate data"
	findings, err := Compare(path, nil, tools, nil)
	if err != nil {
		t.Fatalf("compare failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 drift finding, got %+v", findings)
	}
	if findings[0].RuleID != "ToolDrift01" || findings[0].Severity != auditor.SeverityHigh {
		t.Errorf("unexpected finding: %+v", findings[0])
	}
}

func TestCompareDetectsSchemaDrift(t *testing.T) {
	tools := fixtureTools()
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := Save(path, tools, nil, nil); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	tools[0].InputSchema.Properties["limit"] = schema.JSONSchema{Type: "number"}
	findings, err := Compare(path, nil, tools, nil)
	if err != nil {
		t.Fatalf("compare failed: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != auditor.SeverityMedium {
		t.Errorf("expected medium schema drift, got %+v", findings)
	}
}

func TestCompareDetectsNewAndRemovedTools(t *testing.T) {
	tools := fixtureTools()
	path := writeSnapshot(t, Snapshot{Tools: fingerprints(tools[:1], nil)})
	findings, err := Compare(path, nil, tools, nil)
	if err != nil {
		t.Fatalf("compare failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 new-tool finding, got %+v", findings)
	}
	if findings[0].Severity != auditor.SeverityLow {
		t.Errorf("expected LOW for new tool, got %s", findings[0].Severity)
	}

	path = writeSnapshot(t, Snapshot{Tools: fingerprints(tools, nil)})
	findings, err = Compare(path, nil, tools[:1], nil)
	if err != nil {
		t.Fatalf("compare failed: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != auditor.SeverityMedium {
		t.Errorf("expected medium removed-tool finding, got %+v", findings)
	}
}

type stubCaller struct {
	response json.RawMessage
	err      error
}

func (s stubCaller) CallTool(name string, arguments json.RawMessage) (json.RawMessage, error) {
	return s.response, s.err
}

func TestCompareDetectsBehaviorDrift(t *testing.T) {
	tools := fixtureTools()
	baseline := Snapshot{
		Tools:  fingerprints(tools, nil),
		Shapes: map[string]string{"readFile": responseShapeHash(json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`))},
	}
	path := writeSnapshot(t, baseline)
	changed := stubCaller{response: json.RawMessage(`{"content":[{"type":"image","data":"x"}],"extra":true}`)}
	findings, err := Compare(path, changed, tools, nil)
	if err != nil {
		t.Fatalf("compare failed: %v", err)
	}
	var behavior *auditor.Finding
	for i := range findings {
		if findings[i].RuleID == "BehaviorDrift01" {
			behavior = &findings[i]
		}
	}
	if behavior == nil {
		t.Fatalf("expected behavior drift finding, got %+v", findings)
	}
	if behavior.TargetTool != "readFile" || !behavior.Confirmed {
		t.Errorf("unexpected behavior finding: %+v", *behavior)
	}
}

func TestCompareSkipsBehaviorOnMatchingShape(t *testing.T) {
	tools := fixtureTools()
	response := json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)
	baseline := Snapshot{
		Tools:  fingerprints(tools, nil),
		Shapes: map[string]string{"readFile": responseShapeHash(response)},
	}
	path := writeSnapshot(t, baseline)
	findings, err := Compare(path, stubCaller{response: response}, tools, nil)
	if err != nil {
		t.Fatalf("compare failed: %v", err)
	}
	for _, finding := range findings {
		if finding.RuleID == "BehaviorDrift01" {
			t.Errorf("unexpected behavior drift on identical shape: %+v", finding)
		}
	}
}

func TestShapeKeysIgnoresVolatileValues(t *testing.T) {
	first := responseShapeHash(json.RawMessage(`{"content":[{"type":"text","text":"alpha"}]}`))
	second := responseShapeHash(json.RawMessage(`{"content":[{"type":"text","text":"beta"}]}`))
	if first == "" || first != second {
		t.Errorf("shape must ignore values: %q vs %q", first, second)
	}
	third := responseShapeHash(json.RawMessage(`{"content":[{"type":"image","data":"z"}],"error":"x"}`))
	if third == first {
		t.Error("shape must change with structural changes")
	}
}

func TestCollectShapesSkipsFailures(t *testing.T) {
	shapes := CollectShapes(stubCaller{err: os.ErrDeadlineExceeded}, fixtureTools())
	if len(shapes) != 0 {
		t.Errorf("expected no shapes on failing caller, got %+v", shapes)
	}
}

func TestCompareMissingFile(t *testing.T) {
	if _, err := Compare(filepath.Join(t.TempDir(), "missing.json"), nil, nil, nil); err == nil {
		t.Error("expected error for missing snapshot")
	}
}
