package pollution

import (
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

type stubCaller struct {
	calls   int32
	respond func(call int, arguments json.RawMessage) (json.RawMessage, error)
}

func (s *stubCaller) CallTool(name string, arguments json.RawMessage) (json.RawMessage, error) {
	call := int(atomic.AddInt32(&s.calls, 1))
	return s.respond(call, arguments)
}

func textResponse(text string, isError bool) (json.RawMessage, error) {
	return json.Marshal(probeResponse{Content: []probeContent{{Type: "text", Text: text}}, IsError: isError})
}

func acceptingCaller() *stubCaller {
	return &stubCaller{respond: func(call int, arguments json.RawMessage) (json.RawMessage, error) {
		return textResponse("configuration applied", false)
	}}
}

func validatingCaller() *stubCaller {
	return &stubCaller{respond: func(call int, arguments json.RawMessage) (json.RawMessage, error) {
		var args map[string]json.RawMessage
		if err := json.Unmarshal(arguments, &args); err != nil {
			return nil, err
		}
		if _, exists := args[extraProperty]; exists {
			return textResponse("unknown property rejected", true)
		}
		return textResponse("configuration applied", false)
	}}
}

func demoTool() schema.Tool {
	return schema.Tool{
		Name: "applyConfig",
		InputSchema: schema.JSONSchema{
			Type: "object",
			Properties: map[string]schema.JSONSchema{
				"mode": {Type: "string"},
				"config": {
					Type: "object",
					Properties: map[string]schema.JSONSchema{
						"depth": {Type: "integer"},
					},
					Required: []string{"depth"},
				},
			},
			Required: []string{"mode"},
		},
	}
}

func rootFinding() auditor.Finding {
	return auditor.Finding{
		Severity:   auditor.SeverityMedium,
		RuleID:     "MassAssignment01",
		TargetTool: "applyConfig",
		ParamPath:  "inputSchema",
	}
}

func nestedFinding() auditor.Finding {
	return auditor.Finding{
		Severity:   auditor.SeverityMedium,
		RuleID:     "MassAssignment01",
		TargetTool: "applyConfig",
		ParamPath:  "inputSchema.properties[config]",
	}
}

func TestConfirmFindingsAcceptingServer(t *testing.T) {
	engine := NewEngine(acceptingCaller(), []schema.Tool{demoTool()}, Options{})
	results := engine.ConfirmFindings([]auditor.Finding{rootFinding()})
	if len(results) != 1 || !results[0].Confirmed {
		t.Fatal("expected confirmed mass assignment finding")
	}
	if !strings.Contains(results[0].Evidence, extraProperty) {
		t.Errorf("expected extra property evidence, got %s", results[0].Evidence)
	}
}

func TestConfirmFindingsNestedAcceptingServer(t *testing.T) {
	engine := NewEngine(acceptingCaller(), []schema.Tool{demoTool()}, Options{})
	results := engine.ConfirmFindings([]auditor.Finding{nestedFinding()})
	if !results[0].Confirmed {
		t.Fatal("expected confirmed nested mass assignment finding")
	}
}

func TestConfirmFindingsValidatingServer(t *testing.T) {
	engine := NewEngine(validatingCaller(), []schema.Tool{demoTool()}, Options{})
	results := engine.ConfirmFindings([]auditor.Finding{rootFinding()})
	if results[0].Confirmed {
		t.Error("expected unconfirmed finding against validating server")
	}
}

func TestConfirmFindingsUnknownTool(t *testing.T) {
	engine := NewEngine(acceptingCaller(), []schema.Tool{demoTool()}, Options{})
	finding := rootFinding()
	finding.TargetTool = "missingTool"
	results := engine.ConfirmFindings([]auditor.Finding{finding})
	if results[0].Confirmed {
		t.Error("expected no confirmation for unknown tool")
	}
}

func TestBuildArgumentsRoot(t *testing.T) {
	arguments, err := buildArguments(demoTool().InputSchema, "inputSchema")
	if err != nil {
		t.Fatal(err)
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(arguments, &args); err != nil {
		t.Fatal(err)
	}
	if _, exists := args[extraProperty]; !exists {
		t.Error("expected extra property in root arguments")
	}
	if _, exists := args["mode"]; !exists {
		t.Error("expected required property in root arguments")
	}
}

func TestBuildArgumentsNested(t *testing.T) {
	arguments, err := buildArguments(demoTool().InputSchema, "inputSchema.properties[config]")
	if err != nil {
		t.Fatal(err)
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(arguments, &args); err != nil {
		t.Fatal(err)
	}
	rawConfig, exists := args["config"]
	if !exists {
		t.Fatal("expected config property in arguments")
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(rawConfig, &config); err != nil {
		t.Fatal(err)
	}
	if _, exists := config[extraProperty]; !exists {
		t.Error("expected extra property inside nested config")
	}
	if _, exists := config["depth"]; !exists {
		t.Error("expected nested required property depth")
	}
}

func TestBenignValue(t *testing.T) {
	tests := []struct {
		name string
		prop schema.JSONSchema
		want string
	}{
		{name: "string default", prop: schema.JSONSchema{}, want: `"mcpwnProbeValue"`},
		{name: "integer", prop: schema.JSONSchema{Type: "integer"}, want: `1`},
		{name: "boolean", prop: schema.JSONSchema{Type: "boolean"}, want: `false`},
		{name: "empty array", prop: schema.JSONSchema{Type: "array"}, want: `[]`},
		{name: "array with items", prop: schema.JSONSchema{Type: "array", Items: &schema.JSONSchema{Type: "integer"}}, want: `[1]`},
		{name: "object without required", prop: schema.JSONSchema{Type: "object"}, want: `{}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(benignValue(tc.prop)); got != tc.want {
				t.Errorf("expected %s, got %s", tc.want, got)
			}
		})
	}
}

func TestPropertyChain(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		depth int
	}{
		{name: "root", path: "inputSchema", depth: 0},
		{name: "nested", path: "inputSchema.properties[config]", depth: 1},
		{name: "deep", path: "inputSchema.properties[config].properties[nested]", depth: 2},
		{name: "items", path: "inputSchema.properties[items].items", depth: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := propertyChain(tc.path); len(got) != tc.depth {
				t.Errorf("expected chain depth %d for %s, got %v", tc.depth, tc.path, got)
			}
		})
	}
}
