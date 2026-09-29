package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

func TestRunTerminalOutput(t *testing.T) {
	cfg := Config{TransportType: "stdio", OutputFormat: "terminal"}
	code, err := runWith(context.Background(), cfg, vulnerableTransport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestRunSARIFOutput(t *testing.T) {
	cfg := Config{
		TransportType: "stdio",
		OutputFormat:  "sarif",
		OutputFile:    filepath.Join(t.TempDir(), "report.sarif"),
	}
	code, err := runWith(context.Background(), cfg, vulnerableTransport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	data, err := os.ReadFile(cfg.OutputFile)
	if err != nil {
		t.Fatalf("could not read sarif report: %v", err)
	}
	if !strings.Contains(string(data), `"version": "2.1.0"`) {
		t.Error("expected sarif 2.1.0 version in report")
	}
}

func TestRunJSONToStdout(t *testing.T) {
	cfg := Config{TransportType: "stdio", OutputFormat: "json", OutputFile: ""}
	code, err := runWith(context.Background(), cfg, cleanTransport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestValidationFindingsWithErrors(t *testing.T) {
	tool := schema.Tool{
		Name: "test",
		InputSchema: schema.JSONSchema{
			Type: "not_valid_type",
		},
	}
	findings := validationFindings(tool)
	if len(findings) == 0 {
		t.Fatal("expected validation findings for invalid schema type")
	}
	for _, f := range findings {
		if f.RuleID != "SchemaValidation01" {
			t.Errorf("expected SchemaValidation01, got %s", f.RuleID)
		}
		if f.Severity != auditor.SeverityLow {
			t.Errorf("expected LOW severity, got %s", f.Severity)
		}
	}
}

func TestTargetHintSSE(t *testing.T) {
	cfg := Config{TransportType: "sse", URL: "http://localhost:8080/sse"}
	if got := targetHint(cfg); got != cfg.URL {
		t.Errorf("expected %q, got %q", cfg.URL, got)
	}
}

func TestTargetHintWithArgs(t *testing.T) {
	cfg := Config{
		TransportType: "stdio",
		Command:       "node",
		Args:          []string{"server.js", "--port=3000"},
	}
	hint := targetHint(cfg)
	if !strings.Contains(hint, "node") || !strings.Contains(hint, "server.js") {
		t.Errorf("expected command and args in hint, got %q", hint)
	}
}

func TestTargetHintNoArgs(t *testing.T) {
	cfg := Config{TransportType: "stdio", Command: "node"}
	if got := targetHint(cfg); got != "node" {
		t.Errorf("expected %q, got %q", "node", got)
	}
}

func TestRunFuzzWithCustomPayloads(t *testing.T) {
	content := []byte("payload \"coverageEcho\" {\n    rule = \"CmdInjection01\"\n    template = \"echo {uuid}\"\n    expect = \"{uuid}\"\n}\n")
	payloadFile := filepath.Join(t.TempDir(), "custom.mcpwn")
	if err := os.WriteFile(payloadFile, content, 0600); err != nil {
		t.Fatalf("could not write payload file: %v", err)
	}
	cfg := Config{
		TransportType: "stdio",
		OutputFormat:  "json",
		OutputFile:    filepath.Join(t.TempDir(), "report.json"),
		Fuzz:          true,
		FuzzTimeout:   2 * time.Second,
		Payloads:      payloadFile,
	}
	if _, err := runWith(context.Background(), cfg, reflectingTransport); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunGenPoCNoConfirmedFindings(t *testing.T) {
	cfg := Config{
		TransportType: "stdio",
		OutputFormat:  "json",
		OutputFile:    filepath.Join(t.TempDir(), "report.json"),
		GenPoC:        true,
		PoCDirectory:  t.TempDir(),
	}
	if _, err := runWith(context.Background(), cfg, vulnerableTransport); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
