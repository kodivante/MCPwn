package ui

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/risk"
	"github.com/kodivante/MCPwn/v3/internal/scorer"
	"github.com/kodivante/MCPwn/v3/internal/version"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
)

const promptInjectRulePrefix = "PromptInjection"

func PrintReport(findings []auditor.Finding) {
	renderReport(os.Stdout, findings)
}

func renderReport(w io.Writer, findings []auditor.Finding) {
	if len(findings) == 0 {
		fmt.Fprintf(w, "%s%sNo vulnerabilities found.%s\n", Bold, Cyan, Reset)
		return
	}

	fmt.Fprintf(w, `%sMCPwn Audit Report v%s%s
%sDesigned by kodivante%s
------------------
`, Bold, version.Version, Reset, Cyan, Reset)

	static, injected, advanced := splitFindings(findings)
	renderFindings(w, static)
	if len(injected) > 0 {
		fmt.Fprintf(w, "%s%s--- Prompt Injection Simulation ---%s\n", Bold, Cyan, Reset)
		renderFindings(w, injected)
	}
	if len(advanced) > 0 {
		fmt.Fprintf(w, "%s%s--- Advanced Probes ---%s\n", Bold, Cyan, Reset)
		renderFindings(w, advanced)
	}

	s := scorer.Calculate(findings)
	gradeClr := gradeTerminalColor(s.Grade)
	fmt.Fprintf(w, "%s%sSecurity Score: %s  |  %d CRITICAL  %d HIGH  %d MEDIUM  %d LOW%s\n",
		Bold, gradeClr, string(s.Grade), s.Critical, s.High, s.Medium, s.Low, Reset)

	riskIndex := risk.ServerIndex(findings)
	riskClr := gradeTerminalColor(scorer.Grade(riskIndex.Grade))
	fmt.Fprintf(w, "%s%sRisk Index: %d/100 (%s)  |  chains: %d%s\n",
		Bold, riskClr, riskIndex.Index, riskIndex.Grade, countChains(findings), Reset)
}

func countChains(findings []auditor.Finding) int {
	count := 0
	for _, finding := range findings {
		if strings.HasPrefix(finding.RuleID, "AttackChain") {
			count++
		}
	}
	return count
}

func gradeTerminalColor(g scorer.Grade) string {
	switch g {
	case scorer.GradeA, scorer.GradeB:
		return Cyan
	case scorer.GradeC:
		return Yellow
	default:
		return Red
	}
}

func splitFindings(findings []auditor.Finding) ([]auditor.Finding, []auditor.Finding, []auditor.Finding) {
	var static, injected, advanced []auditor.Finding
	for _, f := range findings {
		switch {
		case strings.HasPrefix(f.RuleID, promptInjectRulePrefix):
			injected = append(injected, f)
		case isAdvancedRule(f.RuleID):
			advanced = append(advanced, f)
		default:
			static = append(static, f)
		}
	}
	return static, injected, advanced
}

func isAdvancedRule(ruleID string) bool {
	advancedPrefixes := []string{
		"StateDesync", "ProtocolRobustness", "RaceCondition", "ResourceExhaustion",
		"ToolRugPull", "TokenLeak", "SamplingAbuse", "SideChannel",
		"ResourceTraversal", "PromptPoisoning", "AttackChain",
		"HttpSession", "HttpOrigin", "HttpAuthBypass", "HttpBatch",
		"ElicitationAbuse", "RootsProbe",
	}
	for _, prefix := range advancedPrefixes {
		if strings.HasPrefix(ruleID, prefix) {
			return true
		}
	}
	return false
}

func renderFindings(w io.Writer, findings []auditor.Finding) {
	for _, f := range findings {
		color := Blue
		switch f.Severity {
		case auditor.SeverityCritical, auditor.SeverityHigh:
			color = Red
		case auditor.SeverityMedium:
			color = Yellow
		}

		indicator := "[?]"
		indicatorColor := Blue
		if f.Confirmed {
			indicator = "[!]"
			indicatorColor = Cyan
		}

		remediation := ""
		if f.Remediation != "" {
			remediation = fmt.Sprintf("  Fix:   %s", f.Remediation)
		}
		evidence := ""
		if f.Evidence != "" {
			evidence = fmt.Sprintf("  Evidence: %s", f.Evidence)
		}

		fmt.Fprintf(w, `%s%s%s [%s%s%s] %s%s%s
  Rule:  %s
  Path:  %s
  Desc:  %s
%s
%s
`, indicatorColor, indicator, Reset, color, f.Severity, Reset, Bold, f.TargetTool, Reset, f.RuleID, f.ParamPath, f.Description, remediation, evidence)
	}
}
