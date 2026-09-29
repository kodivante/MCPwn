package app

import (
	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

func audit(tools []schema.Tool, cfg Config) []auditor.Finding {
	engine := auditor.NewEngineWithOptions(auditor.EngineOptions{EnablePromptInjection: cfg.PromptInject})
	findings := engine.AuditTools(tools)
	for _, tool := range tools {
		findings = append(findings, validationFindings(tool)...)
	}
	return findings
}

func validationFindings(tool schema.Tool) []auditor.Finding {
	errs := schema.ValidateTool(tool)
	if len(errs) == 0 {
		return nil
	}
	findings := make([]auditor.Finding, 0, len(errs))
	for _, validationErr := range errs {
		findings = append(findings, auditor.Finding{
			Severity:    auditor.SeverityLow,
			RuleID:      "SchemaValidation01",
			TargetTool:  tool.Name,
			ParamPath:   validationErr.Path,
			Description: validationErr.Message,
			Remediation: "Fix the inputSchema declaration so agents can validate tool inputs correctly.",
		})
	}
	return findings
}
