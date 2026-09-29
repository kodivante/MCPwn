package graph

import (
	"fmt"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/capability"
)

const chainRuleID = "AttackChain02"

type multiHopPattern struct {
	caps        []string
	anchors     []string
	severity    auditor.Severity
	summary     string
	remediation string
}

var multiHopPatterns = []multiHopPattern{
	{
		caps:        []string{capability.Exec, capability.Credentials, capability.Network},
		anchors:     []string{"TokenLeak01", "CredentialsLeak01"},
		severity:    auditor.SeverityCritical,
		summary:     "Command execution, credential access and network egress combine into a complete data exfiltration pipeline",
		remediation: "Break the pipeline at every hop: restrict execution, isolate secrets and block unauthorized outbound traffic.",
	},
	{
		caps:        []string{capability.Filesystem, capability.Credentials},
		anchors:     []string{"TokenLeak01", "CredentialsLeak01", "PathTraversal01"},
		severity:    auditor.SeverityHigh,
		summary:     "Filesystem access combined with credential exposure enables secret harvesting from disk",
		remediation: "Confine filesystem tools to an allowlisted root and remove secrets from reachable paths.",
	},
	{
		caps:        []string{capability.Network, capability.Exec},
		anchors:     []string{"CmdInjection01", "Ssrf01"},
		severity:    auditor.SeverityHigh,
		summary:     "Network ingestion feeding command execution enables remote takeover through untrusted input",
		remediation: "Never pass fetched remote content into execution sinks; validate and sanitize all inbound data.",
	},
	{
		caps:        []string{capability.Database, capability.Credentials},
		anchors:     []string{"SqlInjection01", "TokenLeak01", "CredentialsLeak01"},
		severity:    auditor.SeverityHigh,
		summary:     "Database access combined with credential exposure enables structured data theft",
		remediation: "Parameterize every query and rotate credentials exposed through tool surfaces.",
	},
	{
		caps:        []string{capability.State, capability.Exec},
		anchors:     []string{"StateMutation01", "CmdInjection01"},
		severity:    auditor.SeverityMedium,
		summary:     "State mutation combined with execution enables persistent footholds inside the server",
		remediation: "Audit state-mutating operations and separate mutation surfaces from execution surfaces.",
	},
}

type ChainSummary struct {
	RuleID   string `json:"ruleId"`
	Severity string `json:"severity"`
	Path     string `json:"path"`
}

func (g Graph) DetectChains(profiles []capability.ToolCapability, findings []auditor.Finding) []auditor.Finding {
	present := make(map[string]bool)
	confirmed := make(map[string]bool)
	targets := make(map[string]string)
	for _, finding := range findings {
		present[finding.RuleID] = true
		confirmed[finding.RuleID] = confirmed[finding.RuleID] || finding.Confirmed
		if _, ok := targets[finding.RuleID]; !ok {
			targets[finding.RuleID] = finding.TargetTool
		}
	}

	serverCaps := capability.ServerCapabilities(profiles)
	var chains []auditor.Finding
	for _, pattern := range multiHopPatterns {
		if !capabilitiesPresent(serverCaps, pattern.caps) {
			continue
		}
		anchor, anchorTool, hasAnchor := pickAnchor(pattern.anchors, present, targets)
		if !hasAnchor {
			continue
		}
		chains = append(chains, chainFinding(pattern, profiles, anchor, anchorTool, confirmedAll(pattern.anchors, present, confirmed)))
	}
	return chains
}

func (g Graph) ChainSummaries(profiles []capability.ToolCapability, findings []auditor.Finding) []ChainSummary {
	detected := g.DetectChains(profiles, findings)
	summaries := make([]ChainSummary, 0, len(detected))
	for _, chain := range detected {
		summaries = append(summaries, ChainSummary{
			RuleID:   chain.RuleID,
			Severity: string(chain.Severity),
			Path:     chain.Evidence,
		})
	}
	return summaries
}

func capabilitiesPresent(serverCaps []string, required []string) bool {
	for _, requiredCap := range required {
		found := false
		for _, serverCap := range serverCaps {
			if serverCap == requiredCap {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func pickAnchor(anchors []string, present map[string]bool, targets map[string]string) (string, string, bool) {
	for _, anchor := range anchors {
		if present[anchor] {
			return anchor, targets[anchor], true
		}
	}
	return "", "", false
}

func confirmedAll(anchors []string, present map[string]bool, confirmed map[string]bool) bool {
	for _, anchor := range anchors {
		if present[anchor] && !confirmed[anchor] {
			return false
		}
	}
	return true
}

func chainFinding(pattern multiHopPattern, profiles []capability.ToolCapability, anchor, anchorTool string, fullyConfirmed bool) auditor.Finding {
	severity := pattern.severity
	if !fullyConfirmed {
		severity = downgrade(severity)
	}
	path := make([]string, 0, len(pattern.caps)+1)
	for _, capabilityName := range pattern.caps {
		if tool, ok := capability.ToolWithCapability(profiles, capabilityName); ok {
			path = append(path, fmt.Sprintf("%s (via %s)", capabilityName, tool))
		} else {
			path = append(path, capabilityName)
		}
	}
	path = append(path, fmt.Sprintf("%s on %s", anchor, anchorTool))
	return auditor.Finding{
		Severity:    severity,
		RuleID:      chainRuleID,
		TargetTool:  "server",
		ParamPath:   "graph",
		Description: pattern.summary,
		Remediation: pattern.remediation,
		Confirmed:   fullyConfirmed,
		Evidence:    "multi-hop path: " + strings.Join(path, " -> "),
	}
}

func downgrade(severity auditor.Severity) auditor.Severity {
	switch severity {
	case auditor.SeverityCritical:
		return auditor.SeverityHigh
	case auditor.SeverityHigh:
		return auditor.SeverityMedium
	default:
		return auditor.SeverityLow
	}
}
