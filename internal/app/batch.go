package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/reporter"
	"github.com/kodivante/MCPwn/v3/internal/scorer"
)

type Target struct {
	Name       string   `json:"name"`
	Transport  string   `json:"transport,omitempty"`
	Command    string   `json:"command,omitempty"`
	Args       []string `json:"args,omitempty"`
	URL        string   `json:"url,omitempty"`
	AuthHeader string   `json:"authHeader,omitempty"`
}

type TargetResult struct {
	Name     string `json:"name"`
	Grade    string `json:"grade"`
	Findings int    `json:"findings"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	ExitCode int    `json:"exitCode"`
	Error    string `json:"error,omitempty"`
}

func RunBatch(ctx context.Context, cfg Config) (int, error) {
	return runBatchWithFactory(ctx, cfg, connect)
}

func runBatchWithFactory(ctx context.Context, cfg Config, connectFactory transportFactory) (int, error) {
	cfg = resolveDeep(cfg)
	if cfg.Watch {
		return 1, fmt.Errorf("-watch cannot be combined with -targets")
	}
	targets, err := loadTargets(cfg.TargetsFile)
	if err != nil {
		return 1, err
	}
	results := make([]TargetResult, 0, len(targets))
	code := 0
	for _, target := range targets {
		result := runBatchTarget(ctx, cfg, target, connectFactory)
		results = append(results, result)
		printTargetResult(result)
		if result.ExitCode > code {
			code = result.ExitCode
		}
	}
	if err := writeBatchInventory(results, cfg); err != nil {
		return 1, err
	}
	return code, nil
}

func runBatchTarget(ctx context.Context, cfg Config, target Target, connectFactory transportFactory) TargetResult {
	targetCfg := targetConfig(cfg, target)
	runCtx := ctx
	if targetCfg.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, targetCfg.Timeout)
		defer cancel()
	}
	findings, err := auditOnce(runCtx, targetCfg, connectFactory)
	if err != nil {
		return TargetResult{Name: target.Name, ExitCode: 1, Error: err.Error()}
	}
	if writeErr := writeTargetReport(cfg, target.Name, findings); writeErr != nil {
		return TargetResult{Name: target.Name, ExitCode: 1, Error: writeErr.Error()}
	}
	return summarizeTarget(target.Name, findings)
}

func targetConfig(cfg Config, target Target) Config {
	override := cfg
	override.TargetsFile = ""
	override.Watch = false
	override.DiffFile = ""
	override.RecordPath = ""
	override.GenPoC = false
	override.OutputFile = ""
	if target.Transport != "" {
		override.TransportType = target.Transport
	}
	override.Command = target.Command
	override.Args = target.Args
	override.URL = target.URL
	override.AuthHeader = target.AuthHeader
	return override
}

func summarizeTarget(name string, findings []auditor.Finding) TargetResult {
	score := scorer.Calculate(findings)
	return TargetResult{
		Name:     name,
		Grade:    string(score.Grade),
		Findings: score.Total,
		Critical: score.Critical,
		High:     score.High,
		Medium:   score.Medium,
		Low:      score.Low,
		ExitCode: exitCode(findings),
	}
}

func loadTargets(path string) ([]Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("targets file read failed: %w", err)
	}
	var targets []Target
	if err := json.Unmarshal(data, &targets); err != nil {
		return nil, fmt.Errorf("targets file parsing failed: %w", err)
	}
	for i := range targets {
		if targets[i].Transport == "" {
			targets[i].Transport = "stdio"
		}
	}
	return targets, nil
}

func printTargetResult(result TargetResult) {
	if result.Error != "" {
		fmt.Printf("%-24s error: %s\n", result.Name, result.Error)
		return
	}
	fmt.Printf("%-24s grade=%s critical=%d high=%d medium=%d low=%d findings=%d\n",
		result.Name, result.Grade, result.Critical, result.High, result.Medium, result.Low, result.Findings)
}

func writeTargetReport(cfg Config, name string, findings []auditor.Finding) error {
	if cfg.OutDirectory == "" {
		return nil
	}
	if err := os.MkdirAll(cfg.OutDirectory, 0755); err != nil {
		return fmt.Errorf("target report directory creation failed: %w", err)
	}
	data, err := reporter.GenerateJSON(findings)
	if err != nil {
		return fmt.Errorf("target report generation failed: %w", err)
	}
	path := filepath.Join(cfg.OutDirectory, sanitizeTargetName(name)+".json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("target report write failed: %w", err)
	}
	return nil
}

func writeBatchInventory(results []TargetResult, cfg Config) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("batch inventory serialization failed: %w", err)
	}
	if cfg.OutputFile != "" {
		if err := os.WriteFile(cfg.OutputFile, data, 0644); err != nil {
			return fmt.Errorf("batch inventory write failed: %w", err)
		}
		return nil
	}
	if cfg.OutputFormat == "json" {
		fmt.Println(string(data))
	}
	return nil
}

func sanitizeTargetName(name string) string {
	cleaned := filepath.Base(name)
	return strings.ReplaceAll(cleaned, string(filepath.Separator), "-")
}
