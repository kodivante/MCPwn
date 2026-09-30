package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

type Policy struct {
	FailOn      []string `json:"failOn"`
	MaxFindings int      `json:"maxFindings"`
	IgnoreRules []string `json:"ignoreRules"`
}

type Violation struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

func Load(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("policy read failed: %w", err)
	}
	var loaded Policy
	if err := json.Unmarshal(data, &loaded); err != nil {
		return Policy{}, fmt.Errorf("policy parsing failed: %w", err)
	}
	return loaded, nil
}

func Evaluate(target Policy, findings []auditor.Finding) ([]Violation, bool) {
	ignored := make(map[string]bool)
	for _, rule := range target.IgnoreRules {
		ignored[rule] = true
	}
	failSeverities := make(map[string]bool)
	for _, severity := range target.FailOn {
		failSeverities[strings.ToUpper(severity)] = true
	}

	count := 0
	severityCounts := make(map[auditor.Severity]int)
	for _, finding := range findings {
		if ignored[finding.RuleID] {
			continue
		}
		count++
		severityCounts[finding.Severity]++
	}

	var violations []Violation
	for severity, tally := range severityCounts {
		if tally > 0 && failSeverities[string(severity)] {
			violations = append(violations, Violation{
				Kind:   "severity-gate",
				Detail: fmt.Sprintf("%d findings with %s severity violate the fail-on gate", tally, severity),
			})
		}
	}
	if target.MaxFindings > 0 && count > target.MaxFindings {
		violations = append(violations, Violation{
			Kind:   "findings-gate",
			Detail: fmt.Sprintf("%d findings exceed the maximum of %d", count, target.MaxFindings),
		})
	}
	return violations, len(violations) > 0
}

func Report(violations []Violation) string {
	if len(violations) == 0 {
		return "Policy: no gate violations.\n"
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "Policy: %d gate violations\n", len(violations))
	for _, violation := range violations {
		fmt.Fprintf(&builder, "  [x] %s: %s\n", violation.Kind, violation.Detail)
	}
	return builder.String()
}
