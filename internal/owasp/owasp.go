package owasp

import (
	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

var ruleMapping = map[string]string{
	"TokenLeak01":                      "MCP01:2025",
	"CredentialsLeak01":                "MCP01:2025",
	"SourceSecret01":                   "MCP01:2025",
	"Idor01":                           "MCP02:2025",
	"MassAssignment01":                 "MCP02:2025",
	"StateMutation01":                  "MCP02:2025",
	"PrototypePollution01":             "MCP02:2025",
	"ToolPoisoning01":                  "MCP03:2025",
	"PromptPoisoning01":                "MCP03:2025",
	"ToolRugPull01":                    "MCP03:2025",
	"DependencyVuln01":                 "MCP04:2025",
	"Typosquat01":                      "MCP04:2025",
	"UnpinnedDep01":                    "MCP04:2025",
	"CmdInjection01":                   "MCP05:2025",
	"SourceTaint01":                    "MCP05:2025",
	"CorrelatedVuln01":                 "MCP05:2025",
	"SqlInjection01":                   "MCP05:2025",
	"NoSqlInjection01":                 "MCP05:2025",
	"TemplateInjection01":              "MCP05:2025",
	"UnsafeDeserialization01":          "MCP05:2025",
	"SourceExec01":                     "MCP05:2025",
	"SourceDeserialization01":          "MCP05:2025",
	"PromptInjection01":                "MCP06:2025",
	"PromptInjectionReflection":        "MCP06:2025",
	"PromptInjectionPartialReflection": "MCP06:2025",
	"HttpAuthBypass01":                 "MCP07:2025",
	"OAuthMetadata01":                  "MCP07:2025",
	"OAuthPkce01":                      "MCP07:2025",
	"TokenPassthrough01":               "MCP07:2025",
	"PathTraversal01":                  "MCP10:2025",
	"ResourceTraversal01":              "MCP10:2025",
	"ContextSharing01":                 "MCP10:2025",
}

type CoverageItem struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Status   string `json:"status"`
	Findings int    `json:"findings"`
}

var catalog = []CoverageItem{
	{ID: "MCP01:2025", Title: "Token Mismanagement and Secret Exposure", Status: "covered"},
	{ID: "MCP02:2025", Title: "Privilege Escalation via Scope Creep", Status: "covered"},
	{ID: "MCP03:2025", Title: "Tool Poisoning", Status: "covered"},
	{ID: "MCP04:2025", Title: "Software Supply Chain Attacks and Dependency Tampering", Status: "covered"},
	{ID: "MCP05:2025", Title: "Command Injection and Execution", Status: "covered"},
	{ID: "MCP06:2025", Title: "Prompt Injection via Contextual Payloads", Status: "covered"},
	{ID: "MCP07:2025", Title: "Insufficient Authentication and Authorization", Status: "covered"},
	{ID: "MCP08:2025", Title: "Lack of Audit and Telemetry", Status: "partial"},
	{ID: "MCP09:2025", Title: "Shadow MCP Servers", Status: "partial"},
	{ID: "MCP10:2025", Title: "Context Injection and Over-Sharing", Status: "covered"},
}

func MapRule(ruleID string) string {
	return ruleMapping[ruleID]
}

func CoverageSummary(findings []auditor.Finding) []CoverageItem {
	items := make([]CoverageItem, len(catalog))
	copy(items, catalog)
	counts := make(map[string]int)
	for _, finding := range findings {
		if id, ok := ruleMapping[finding.RuleID]; ok {
			counts[id]++
		}
	}
	for i := range items {
		items[i].Findings = counts[items[i].ID]
	}
	return items
}
