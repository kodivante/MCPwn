package app

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

type diffResult struct {
	added     []auditor.Finding
	fixed     []auditor.Finding
	unchanged []auditor.Finding
}

func findingKey(f auditor.Finding) string {
	return f.RuleID + "|" + f.TargetTool + "|" + f.ParamPath
}

func loadBaselineFindings(path string) ([]auditor.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("diff baseline read failed: %w", err)
	}
	var findings []auditor.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("diff baseline parsing failed: %w", err)
	}
	return findings, nil
}

func diffFindings(current, baseline []auditor.Finding) diffResult {
	baseKeys := make(map[string]bool, len(baseline))
	for _, f := range baseline {
		baseKeys[findingKey(f)] = true
	}
	currKeys := make(map[string]bool, len(current))
	for _, f := range current {
		currKeys[findingKey(f)] = true
	}
	var result diffResult
	for _, f := range current {
		if baseKeys[findingKey(f)] {
			result.unchanged = append(result.unchanged, f)
		} else {
			result.added = append(result.added, f)
		}
	}
	for _, f := range baseline {
		if !currKeys[findingKey(f)] {
			result.fixed = append(result.fixed, f)
		}
	}
	return result
}

func runDiff(current []auditor.Finding, baselinePath string) error {
	baseline, err := loadBaselineFindings(baselinePath)
	if err != nil {
		return err
	}
	printDiff(diffFindings(current, baseline))
	return nil
}

func printDiff(r diffResult) {
	fmt.Fprintf(os.Stderr, `
-- Diff Report --
New:       %d
Fixed:     %d
Unchanged: %d
`, len(r.added), len(r.fixed), len(r.unchanged))
	for _, f := range r.added {
		fmt.Fprintf(os.Stderr, "[NEW]   %s %s %s\n", f.Severity, f.RuleID, f.TargetTool)
	}
	for _, f := range r.fixed {
		fmt.Fprintf(os.Stderr, "[FIXED] %s %s %s\n", f.Severity, f.RuleID, f.TargetTool)
	}
}
