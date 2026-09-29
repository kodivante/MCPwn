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

const vulnerableToolsPayload = `{"tools":[{"name":"system_exec","description":"Execute an OS command","inputSchema":{"type":"object","properties":{"cmd":{"type":"string","description":"The command to run"}},"required":["cmd"],"additionalProperties":false}}]}`

const cleanToolsPayload = `{"tools":[{"name":"list_items","inputSchema":{"type":"object","properties":{"pageNumber":{"type":"number"}},"additionalProperties":false}}]}`

func vulnerableTransport(ctx context.Context, cfg Config) (client.Transport, error) {
	conn := testutil.Pipe(vulnerableToolsPayload)
	return client.NewStreamTransport(conn, conn), nil
}

func cleanTransport(ctx context.Context, cfg Config) (client.Transport, error) {
	conn := testutil.Pipe(cleanToolsPayload)
	return client.NewStreamTransport(conn, conn), nil
}

func reflectingTransport(ctx context.Context, cfg Config) (client.Transport, error) {
	conn := testutil.PipeReflecting(vulnerableToolsPayload)
	return client.NewStreamTransport(conn, conn), nil
}

func TestRunReportsCriticalFindings(t *testing.T) {
	cfg := Config{
		TransportType: "stdio",
		OutputFormat:  "json",
		OutputFile:    filepath.Join(t.TempDir(), "report.json"),
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
		t.Fatalf("unexpected report read error: %v", err)
	}
	if !strings.Contains(string(data), "CmdInjection01") {
		t.Errorf("expected CmdInjection01 in report, got %s", data)
	}
}

func TestRunCleanToolsExitZero(t *testing.T) {
	cfg := Config{
		TransportType: "stdio",
		OutputFormat:  "json",
		OutputFile:    filepath.Join(t.TempDir(), "report.json"),
	}

	code, err := runWith(context.Background(), cfg, cleanTransport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	data, err := os.ReadFile(cfg.OutputFile)
	if err != nil {
		t.Fatalf("unexpected report read error: %v", err)
	}
	if strings.Contains(string(data), "CmdInjection01") {
		t.Errorf("unexpected CmdInjection01 in clean report: %s", data)
	}
}

func TestRunFuzzConfirmsFindings(t *testing.T) {
	cfg := Config{
		TransportType: "stdio",
		OutputFormat:  "json",
		OutputFile:    filepath.Join(t.TempDir(), "report.json"),
		Fuzz:          true,
		FuzzTimeout:   2 * time.Second,
	}

	code, err := runWith(context.Background(), cfg, reflectingTransport)
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
	if !strings.Contains(string(data), `"Confirmed": true`) {
		t.Errorf("expected confirmed finding in report: %s", data)
	}
	if !strings.Contains(string(data), `"Evidence": "marker`) {
		t.Errorf("expected marker evidence in report: %s", data)
	}
}

func TestRunFuzzUnconfirmedWithFixedMock(t *testing.T) {
	cfg := Config{
		TransportType: "stdio",
		OutputFormat:  "json",
		OutputFile:    filepath.Join(t.TempDir(), "report.json"),
		Fuzz:          true,
		FuzzTimeout:   2 * time.Second,
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
		t.Fatalf("unexpected report read error: %v", err)
	}
	if strings.Contains(string(data), `"Confirmed": true`) {
		t.Errorf("expected no confirmations against sanitizing mock: %s", data)
	}
}

func TestRunHTMLOutput(t *testing.T) {
	cfg := Config{
		TransportType: "stdio",
		OutputFormat:  "html",
		OutputFile:    filepath.Join(t.TempDir(), "report.html"),
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
		t.Fatalf("unexpected report read error: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Error("expected html doctype in report")
	}
	if !strings.Contains(out, "CmdInjection01") {
		t.Error("expected finding rule in html report")
	}
}

func TestRunPromptInjectReflection(t *testing.T) {
	cfg := Config{
		TransportType: "stdio",
		OutputFormat:  "json",
		OutputFile:    filepath.Join(t.TempDir(), "report.json"),
		PromptInject:  true,
	}

	code, err := runWith(context.Background(), cfg, reflectingTransport)
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
	if !strings.Contains(string(data), "PromptInjectionReflection") {
		t.Errorf("expected prompt injection finding in report: %s", data)
	}
}

func TestRunGenPoCWritesFiles(t *testing.T) {
	pocsDir := filepath.Join(t.TempDir(), "pocs")
	cfg := Config{
		TransportType: "stdio",
		OutputFormat:  "json",
		OutputFile:    filepath.Join(t.TempDir(), "report.json"),
		Fuzz:          true,
		FuzzTimeout:   2 * time.Second,
		GenPoC:        true,
		PoCDirectory:  pocsDir,
	}

	code, err := runWith(context.Background(), cfg, reflectingTransport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	data, err := os.ReadFile(filepath.Join(pocsDir, "CmdInjection01_system_exec.py"))
	if err != nil {
		t.Fatalf("expected poc file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "MCPwn Proof of Concept") {
		t.Error("expected poc header in generated file")
	}
	if !strings.Contains(content, "[+] PoC executed") {
		t.Error("expected success marker in generated file")
	}
}

func TestRunInvalidOutputFormat(t *testing.T) {
	cfg := Config{TransportType: "stdio", OutputFormat: "xml"}
	if _, err := runWith(context.Background(), cfg, cleanTransport); err == nil {
		t.Error("expected invalid output format error")
	}
}

func TestConnectValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "missing command", cfg: Config{TransportType: "stdio"}},
		{name: "missing url", cfg: Config{TransportType: "sse"}},
		{name: "invalid transport type", cfg: Config{TransportType: "invalid"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := connect(context.Background(), tc.cfg); err == nil {
				t.Error("expected connect error")
			}
		})
	}
}
