package auditor

import (
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

type Finding struct {
	Severity    Severity `json:"Severity"`
	RuleID      string   `json:"RuleID"`
	TargetTool  string   `json:"TargetTool"`
	ParamPath   string   `json:"ParamPath"`
	Description string   `json:"Description"`
	Remediation string   `json:"Remediation"`
	Confirmed   bool     `json:"Confirmed,omitempty"`
	Evidence    string   `json:"Evidence,omitempty"`
}

type Engine struct {
	rules []Rule
}

type EngineOptions struct {
	EnablePromptInjection bool
}

func NewEngine() *Engine {
	return &Engine{
		rules: []Rule{
			&ToolPoisoningRule{},
			&CommandInjectionRule{},
			&PathTraversalRule{},
			&SSRFRule{},
			&CredentialsLeakRule{},
			&SQLInjectionRule{},
			&IdorRule{},
			&MassAssignmentRule{},
			&DosRule{},
			&StateMutationRule{},
			&WeakTypingRule{},
			&MissingRequiredRule{},
		},
	}
}

func NewEngineWithOptions(options EngineOptions) *Engine {
	engine := NewEngine()
	if options.EnablePromptInjection {
		engine.rules = append(engine.rules, &PromptInjectionRule{})
	}
	return engine
}

func (e *Engine) AuditTools(tools []schema.Tool) []Finding {
	var findings []Finding
	for _, tool := range tools {
		for _, rule := range e.rules {
			findings = append(findings, rule.Evaluate(tool)...)
		}
	}
	return findings
}
