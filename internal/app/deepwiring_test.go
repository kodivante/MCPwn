package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/client"
	"github.com/kodivante/MCPwn/v3/internal/testutil"
)

const deepToolsPayload = `{"tools":[{"name":"system_exec","description":"Execute an OS command","inputSchema":{"type":"object","properties":{"cmd":{"type":"string","description":"The command to run"}},"required":["cmd"]}}]}`

func deepTransport(ctx context.Context, cfg Config) (client.Transport, error) {
	conn := testutil.PipeReflecting(deepToolsPayload)
	return client.NewStreamTransport(conn, conn), nil
}

func TestResolveDeep(t *testing.T) {
	enabled := resolveDeep(Config{Deep: true})
	if !enabled.Fuzz || !enabled.PromptInject || !enabled.Traversal || !enabled.SSRF ||
		!enabled.Pollute || !enabled.Desync || !enabled.ProtoFuzz || !enabled.RaceProbe || !enabled.Exhaust {
		t.Error("expected -deep to enable every dynamic engine")
	}

	plain := resolveDeep(Config{})
	if plain.Fuzz || plain.Traversal || plain.Desync {
		t.Error("expected resolveDeep to leave config untouched without -deep")
	}
}

func TestRunDeepFullBattery(t *testing.T) {
	cfg := Config{
		TransportType: "stdio",
		OutputFormat:  "json",
		OutputFile:    filepath.Join(t.TempDir(), "report.json"),
		Deep:          true,
		FuzzTimeout:   2 * time.Second,
	}

	code, err := runWith(context.Background(), cfg, deepTransport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	data, err := os.ReadFile(cfg.OutputFile)
	if err != nil {
		t.Fatalf("unexpected report read error: %v", err)
	}
	out := string(data)

	for _, want := range []string{
		`"Confirmed": true`,
		"StateDesync01",
		"PromptInjectionReflection",
		"MassAssignment01",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %s in deep report", want)
		}
	}
	if strings.Contains(out, "ProtocolRobustness01") {
		t.Error("expected the resilient mock to survive protocol fuzzing")
	}
}

func TestRunDeepQuickSkipsRemainingEngines(t *testing.T) {
	cfg := Config{
		TransportType: "stdio",
		OutputFormat:  "json",
		OutputFile:    filepath.Join(t.TempDir(), "report.json"),
		Deep:          true,
		Quick:         true,
		FuzzTimeout:   2 * time.Second,
	}

	code, err := runWith(context.Background(), cfg, deepTransport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	data, err := os.ReadFile(cfg.OutputFile)
	if err != nil {
		t.Fatalf("unexpected report read error: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, `"Confirmed": true`) {
		t.Error("expected at least one confirmation before quick exit")
	}
	if strings.Contains(out, "StateDesync01") {
		t.Error("expected quick mode to skip lifecycle probes after the first confirmation")
	}
}
