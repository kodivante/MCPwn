package app

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/pocgen"
)

const pocsDirectory = "pocs"

func generatePoCs(findings []auditor.Finding, cfg Config) error {
	confirmed := confirmedFindings(findings)
	if len(confirmed) == 0 {
		fmt.Fprintln(os.Stderr, "mcpwn: no confirmed findings, run with -fuzz before generating proofs of concept")
		return nil
	}
	directory := cfg.PoCDirectory
	if directory == "" {
		directory = pocsDirectory
	}
	if err := os.MkdirAll(directory, 0755); err != nil {
		return fmt.Errorf("poc directory creation failed: %w", err)
	}
	for _, finding := range confirmed {
		poc, err := pocgen.Generate(finding, pocgen.Options{Target: targetHint(cfg), Language: cfg.PoCLang})
		if err != nil {
			return err
		}
		path := filepath.Join(directory, poc.Name)
		if err := os.WriteFile(path, poc.Content, 0644); err != nil {
			return fmt.Errorf("poc write failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "mcpwn: proof of concept written to %s\n", path)
	}
	return nil
}

func confirmedFindings(findings []auditor.Finding) []auditor.Finding {
	var confirmed []auditor.Finding
	for _, f := range findings {
		if f.Confirmed {
			confirmed = append(confirmed, f)
		}
	}
	return confirmed
}
