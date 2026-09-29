package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/client"
	"github.com/kodivante/MCPwn/v3/internal/testutil"
)

const mockToolsPayload = `{"tools":[{"name":"system_exec","inputSchema":{"type":"object","properties":{"cmd":{"type":"string"}}}}]}`

func pipeFactory(toolsPayload string) transportFactory {
	return func(ctx context.Context, cfg Config) (client.Transport, error) {
		conn := testutil.Pipe(toolsPayload)
		return client.NewStreamTransport(conn, conn), nil
	}
}

func writeTargetsFile(t *testing.T, targets []Target) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.json")
	data, err := json.Marshal(targets)
	if err != nil {
		t.Fatalf("targets serialization failed: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("targets file write failed: %v", err)
	}
	return path
}

func TestRunBatchAuditsEveryTarget(t *testing.T) {
	targets := []Target{
		{Name: "vulnerable", Transport: "stdio", Command: "mock"},
		{Name: "clean", Transport: "stdio", Command: "mock"},
	}
	cfg := Config{
		TargetsFile:  writeTargetsFile(t, targets),
		OutputFormat: "terminal",
	}
	factory := func(ctx context.Context, cfg Config) (client.Transport, error) {
		if cfg.Command == "mock" {
			conn := testutil.Pipe(mockToolsPayload)
			return client.NewStreamTransport(conn, conn), nil
		}
		conn := testutil.Pipe(`{"tools":[]}`)
		return client.NewStreamTransport(conn, conn), nil
	}
	code, err := runBatchWithFactory(context.Background(), cfg, factory)
	if err != nil {
		t.Fatalf("batch run failed: %v", err)
	}
	if code != 1 {
		t.Errorf("expected exit code 1 with critical findings, got %d", code)
	}
}

func TestRunBatchWritesInventoryAndReports(t *testing.T) {
	outDir := t.TempDir()
	targets := []Target{{Name: "vulnerable", Transport: "stdio", Command: "mock"}}
	cfg := Config{
		TargetsFile:  writeTargetsFile(t, targets),
		OutputFile:   filepath.Join(outDir, "inventory.json"),
		OutDirectory: filepath.Join(outDir, "reports"),
	}
	code, err := runBatchWithFactory(context.Background(), cfg, pipeFactory(mockToolsPayload))
	if err != nil {
		t.Fatalf("batch run failed: %v", err)
	}
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	inventoryData, err := os.ReadFile(cfg.OutputFile)
	if err != nil {
		t.Fatalf("inventory read failed: %v", err)
	}
	var results []TargetResult
	if err := json.Unmarshal(inventoryData, &results); err != nil {
		t.Fatalf("inventory parsing failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Grade == "" || results[0].Error != "" {
		t.Errorf("unexpected result: %+v", results[0])
	}
	if results[0].Critical < 1 {
		t.Errorf("expected critical findings in result: %+v", results[0])
	}
	reportPath := filepath.Join(cfg.OutDirectory, "vulnerable.json")
	if _, err := os.Stat(reportPath); err != nil {
		t.Errorf("expected per-target report at %s: %v", reportPath, err)
	}
}

func TestRunBatchContinuesOnError(t *testing.T) {
	targets := []Target{
		{Name: "broken", Transport: "stdio", Command: "broken"},
		{Name: "working", Transport: "stdio", Command: "mock"},
	}
	cfg := Config{
		TargetsFile:  writeTargetsFile(t, targets),
		OutputFormat: "terminal",
	}
	factory := func(ctx context.Context, cfg Config) (client.Transport, error) {
		if cfg.Command == "broken" {
			return nil, os.ErrPermission
		}
		conn := testutil.Pipe(mockToolsPayload)
		return client.NewStreamTransport(conn, conn), nil
	}
	code, err := runBatchWithFactory(context.Background(), cfg, factory)
	if err != nil {
		t.Fatalf("batch run failed: %v", err)
	}
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestRunBatchRejectsWatchMode(t *testing.T) {
	cfg := Config{TargetsFile: "targets.json", Watch: true}
	if _, err := runBatchWithFactory(context.Background(), cfg, pipeFactory(mockToolsPayload)); err == nil {
		t.Error("expected error combining watch with batch")
	}
}

func TestLoadTargetsDefaultsTransport(t *testing.T) {
	path := writeTargetsFile(t, []Target{{Name: "bare", Command: "mock"}})
	targets, err := loadTargets(path)
	if err != nil {
		t.Fatalf("loadTargets failed: %v", err)
	}
	if targets[0].Transport != "stdio" {
		t.Errorf("expected default stdio transport, got %s", targets[0].Transport)
	}
}

func TestLoadTargetsMissingFile(t *testing.T) {
	if _, err := loadTargets(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("expected error for missing targets file")
	}
}
