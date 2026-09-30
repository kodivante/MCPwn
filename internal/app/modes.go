package app

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kodivante/MCPwn/v3/internal/attackchain"
	"github.com/kodivante/MCPwn/v3/internal/correlation"
	"github.com/kodivante/MCPwn/v3/internal/discovery"
)

func RunDiscover(cfg Config) (int, error) {
	servers, err := discovery.Discover()
	if err != nil {
		return 1, fmt.Errorf("discovery failed: %w", err)
	}
	fmt.Print(discovery.PrintInventory(servers))
	if cfg.OutputFormat == "json" {
		data, err := json.MarshalIndent(servers, "", "  ")
		if err != nil {
			return 1, fmt.Errorf("inventory serialization failed: %w", err)
		}
		if err := writeReport(data, cfg.OutputFile); err != nil {
			return 1, err
		}
	}
	return 0, nil
}

func RunSourceScan(ctx context.Context, cfg Config) (int, error) {
	findings, err := localScanFindings(cfg)
	if err != nil {
		return 1, err
	}
	artifacts := auditArtifacts{}
	taintFindings, taintErr := runTaintAnalysis(cfg, &artifacts)
	if taintErr != nil {
		return 1, taintErr
	}
	findings = append(findings, taintFindings...)
	findings = append(findings, correlation.Correlate(findings, artifacts.taintPaths)...)
	applyConfidence(findings)
	findings = attackchain.NewDetector().Analyze(findings)
	if err := render(findings, artifacts, cfg); err != nil {
		return 1, err
	}
	if cfg.DiffFile != "" {
		if err := runDiff(findings, cfg.DiffFile); err != nil {
			return 1, err
		}
	}
	return exitCode(findings), nil
}
