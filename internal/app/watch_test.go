package app

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/client"
)

func TestWatchLoopRunsUntilCancel(t *testing.T) {
	var runs int32
	factory := func(ctx context.Context, cfg Config) (client.Transport, error) {
		atomic.AddInt32(&runs, 1)
		return vulnerableTransport(ctx, cfg)
	}
	cfg := Config{
		TransportType: "stdio",
		OutputFormat:  "json",
		OutputFile:    filepath.Join(t.TempDir(), "report.json"),
		Watch:         true,
		WatchInterval: 20 * time.Millisecond,
		Timeout:       2 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(120 * time.Millisecond)
		cancel()
	}()

	code, err := watchLoop(ctx, cfg, factory)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if got := atomic.LoadInt32(&runs); got < 2 {
		t.Errorf("expected at least 2 audit runs before cancel, got %d", got)
	}
}

func TestWatchLoopDefaultInterval(t *testing.T) {
	cfg := Config{
		TransportType: "stdio",
		OutputFormat:  "json",
		OutputFile:    filepath.Join(t.TempDir(), "report.json"),
		Timeout:       2 * time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	code, err := watchLoop(ctx, cfg, vulnerableTransport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestRunOnceWithoutTimeout(t *testing.T) {
	cfg := Config{
		TransportType: "stdio",
		OutputFormat:  "json",
		OutputFile:    filepath.Join(t.TempDir(), "report.json"),
		Timeout:       0,
	}
	code, err := runOnce(context.Background(), cfg, vulnerableTransport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}
