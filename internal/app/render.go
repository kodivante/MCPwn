package app

import (
	"fmt"
	"os"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/reporter"
	"github.com/kodivante/MCPwn/v3/internal/scorer"
	"github.com/kodivante/MCPwn/v3/internal/ui"
)

func render(findings []auditor.Finding, artifacts auditArtifacts, cfg Config) error {
	switch cfg.OutputFormat {
	case "json":
		data, err := reporter.GenerateJSON(findings)
		if err != nil {
			return err
		}
		return writeReport(data, cfg.OutputFile)
	case "sarif":
		data, err := reporter.GenerateSARIF(findings)
		if err != nil {
			return err
		}
		return writeReport(data, cfg.OutputFile)
	case "html":
		data, err := reporter.GenerateHTML(findings)
		if err != nil {
			return err
		}
		return writeReport(data, cfg.OutputFile)
	case "graph":
		data, err := reporter.GenerateGraphReport(findings, artifacts.profiles, artifacts.entityGraph, artifacts.campaign)
		if err != nil {
			return err
		}
		return writeReport(data, cfg.OutputFile)
	case "terminal":
		ui.PrintReport(findings)
		return nil
	case "badge":
		return writeReport(reporter.GenerateBadge(scorer.Calculate(findings)), cfg.OutputFile)
	default:
		return fmt.Errorf("invalid output format: %s", cfg.OutputFormat)
	}
}

func writeReport(data []byte, path string) error {
	if path == "" {
		fmt.Println(string(data))
		return nil
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("report write failed: %w", err)
	}
	return nil
}

func exitCode(findings []auditor.Finding) int {
	for _, f := range findings {
		if f.Severity == auditor.SeverityCritical || f.Severity == auditor.SeverityHigh {
			return 1
		}
	}
	return 0
}
