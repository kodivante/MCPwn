package correlation

import (
	"fmt"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/taint"
)

const ruleID = "CorrelatedVuln01"

var classRules = map[string][]string{
	"exec":            {"CmdInjection01", "MutationDiff01"},
	"network":         {"Ssrf01"},
	"filesystem":      {"PathTraversal01", "ResourceTraversal01"},
	"database":        {"SqlInjection01"},
	"deserialization": {"UnsafeDeserialization01"},
}

func Correlate(findings []auditor.Finding, paths []taint.Path) []auditor.Finding {
	confirmedByTool := make(map[string]map[string]auditor.Finding)
	for _, finding := range findings {
		if !finding.Confirmed {
			continue
		}
		if confirmedByTool[finding.TargetTool] == nil {
			confirmedByTool[finding.TargetTool] = make(map[string]auditor.Finding)
		}
		confirmedByTool[finding.TargetTool][finding.RuleID] = finding
	}

	var correlations []auditor.Finding
	seen := make(map[string]bool)
	for _, path := range paths {
		rules, ok := classRules[path.SinkClass]
		if !ok {
			continue
		}
		for _, rule := range rules {
			dynamic, confirmed := confirmedByTool[path.Tool][rule]
			if !confirmed {
				continue
			}
			key := path.Tool + "|" + path.SinkClass
			if seen[key] {
				break
			}
			seen[key] = true
			correlations = append(correlations, correlatedFinding(path, dynamic))
			break
		}
	}
	return correlations
}

func correlatedFinding(path taint.Path, dynamic auditor.Finding) auditor.Finding {
	return auditor.Finding{
		Severity:     auditor.SeverityCritical,
		RuleID:       ruleID,
		TargetTool:   path.Tool,
		ParamPath:    "correlation:" + path.SinkClass,
		Description:  fmt.Sprintf("Static source-to-sink path and runtime behavior both confirm a %s vulnerability on this tool", path.SinkClass),
		Remediation:  "Fix the tainted path reported statically and the exploitability confirmed at runtime; treat this as a verified vulnerability, not a hypothesis.",
		Confirmed:    true,
		Verification: "correlated",
		Evidence: fmt.Sprintf("static path: %s | runtime: %s confirmed (%s)",
			path.Evidence(), dynamic.RuleID, truncate(dynamic.Evidence, 160)),
	}
}

func EnrichSupplyChain(findings []auditor.Finding, paths []taint.Path) []auditor.Finding {
	enriched := make([]auditor.Finding, len(findings))
	copy(enriched, findings)
	for index := range enriched {
		if enriched[index].RuleID != "DependencyVuln01" {
			continue
		}
		dependency := enriched[index].TargetTool
		for _, path := range paths {
			if touchesPackage(path, dependency) {
				enriched[index].Evidence += fmt.Sprintf(" | exercised by taint path: %s", truncate(path.Evidence(), 120))
				break
			}
		}
	}
	return enriched
}

func touchesPackage(path taint.Path, dependency string) bool {
	for _, hop := range path.Hops {
		if strings.HasPrefix(hop.Function, dependency+".") {
			return true
		}
	}
	return false
}

func truncate(text string, max int) string {
	if len(text) <= max {
		return text
	}
	return text[:max] + "..."
}
