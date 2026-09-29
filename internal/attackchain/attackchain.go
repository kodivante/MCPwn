package attackchain

import (
	"fmt"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

const ruleID = "AttackChain01"

type chainLink struct {
	RuleID string
	Reason string
}

type chainPattern struct {
	Links    []string
	Severity auditor.Severity
	Summary  string
}

var chainPatterns = []chainPattern{
	{
		Links:    []string{"CmdInjection01", "TokenLeak01"},
		Severity: auditor.SeverityCritical,
		Summary:  "Remote code execution combined with credential disclosure enables full host takeover",
	},
	{
		Links:    []string{"Ssrf01", "TokenLeak01"},
		Severity: auditor.SeverityCritical,
		Summary:  "SSRF with leaked credentials enables impersonation of internal services and lateral movement",
	},
	{
		Links:    []string{"CmdInjection01", "CredentialsLeak01"},
		Severity: auditor.SeverityCritical,
		Summary:  "Command execution with exposed credentials enables complete environment compromise",
	},
	{
		Links:    []string{"PathTraversal01", "CredentialsLeak01"},
		Severity: auditor.SeverityHigh,
		Summary:  "Arbitrary file read with credential exposure enables secret harvesting across the host",
	},
	{
		Links:    []string{"PromptInjection01", "Ssrf01"},
		Severity: auditor.SeverityHigh,
		Summary:  "Prompt injection chained with SSRF enables silent data exfiltration toward attacker endpoints",
	},
	{
		Links:    []string{"MassAssignment01", "StateMutation01"},
		Severity: auditor.SeverityHigh,
		Summary:  "Mass assignment combined with state mutation enables privilege escalation through undocumented fields",
	},
	{
		Links:    []string{"Idor01", "StateMutation01"},
		Severity: auditor.SeverityHigh,
		Summary:  "IDOR with mutable state enables cross-user data manipulation",
	},
	{
		Links:    []string{"SqlInjection01", "TokenLeak01"},
		Severity: auditor.SeverityCritical,
		Summary:  "SQL injection with leaked credentials enables database takeover",
	},
}

type Detector struct{}

func NewDetector() *Detector {
	return &Detector{}
}

func (d *Detector) Analyze(findings []auditor.Finding) []auditor.Finding {
	chains := detectChains(findings)
	results := make([]auditor.Finding, 0, len(findings)+len(chains))
	results = append(results, findings...)
	results = append(results, chains...)
	return results
}

func detectChains(findings []auditor.Finding) []auditor.Finding {
	present := make(map[string]bool)
	for _, finding := range findings {
		present[finding.RuleID] = true
	}

	var chains []auditor.Finding
	for _, pattern := range chainPatterns {
		if allPresent(pattern.Links, present) {
			chains = append(chains, chainFinding(pattern, findings))
		}
	}
	return chains
}

func allPresent(links []string, present map[string]bool) bool {
	for _, link := range links {
		if !present[link] {
			return false
		}
	}
	return true
}

func chainFinding(pattern chainPattern, findings []auditor.Finding) auditor.Finding {
	links := make([]chainLink, 0, len(pattern.Links))
	for _, rule := range pattern.Links {
		links = append(links, chainLink{RuleID: rule, Reason: describeRule(rule, findings)})
	}
	evidence := formatLinks(links)
	return auditor.Finding{
		Severity:    pattern.Severity,
		RuleID:      ruleID,
		TargetTool:  "server",
		ParamPath:   "chain",
		Description: pattern.Summary,
		Remediation: "Fix every link of this chain. Individual fixes on each finding break the attack path; prioritize the confirmed links first.",
		Evidence:    evidence,
	}
}

func describeRule(ruleID string, findings []auditor.Finding) string {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return fmt.Sprintf("%s on %s", ruleID, finding.TargetTool)
		}
	}
	return ruleID
}

func formatLinks(links []chainLink) string {
	parts := make([]string, 0, len(links))
	for _, link := range links {
		parts = append(parts, link.RuleID+" ("+link.Reason+")")
	}
	return "chain: " + strings.Join(parts, " -> ")
}
