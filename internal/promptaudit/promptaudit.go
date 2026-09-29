package promptaudit

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/client"
)

const ruleID = "PromptPoisoning01"

var exfiltrationKeywords = []string{
	"exfiltrate", "send to", "post to", "upload to",
	"http://", "https://", "curl ", "wget ",
	"webhook", "callback", "external server",
}

var roleManipulation = []string{
	"ignore previous", "disregard previous", "system prompt",
	"you are now", "act as", "jailbreak",
	"override instructions", "secret instructions",
	"do not reveal", "do not tell the user",
	"hide this", "without the user",
}

type Options struct{}

type Engine struct {
	session *client.Session
}

func NewEngine(session *client.Session, options Options) *Engine {
	return &Engine{session: session}
}

func (e *Engine) Probe() []auditor.Finding {
	prompts, err := e.session.ListPrompts()
	if err != nil {
		return nil
	}

	var findings []auditor.Finding
	for _, prompt := range prompts {
		findings = append(findings, e.auditPrompt(prompt)...)
	}
	return findings
}

func (e *Engine) auditPrompt(prompt client.Prompt) []auditor.Finding {
	var findings []auditor.Finding
	if finding, ok := scanText(prompt.Description, prompt.Name); ok {
		findings = append(findings, finding)
	}
	messages, err := e.session.GetPrompt(prompt.Name, promptArguments(prompt))
	if err != nil {
		return findings
	}
	for _, message := range messages.Messages {
		text := extractText(message.Content)
		if finding, ok := scanText(text, prompt.Name); ok {
			findings = append(findings, finding)
		}
	}
	return dedupe(findings)
}

func promptArguments(prompt client.Prompt) map[string]string {
	arguments := make(map[string]string)
	for _, arg := range prompt.Arguments {
		if arg.Required {
			arguments[arg.Name] = "mcpwnAuditValue"
		}
	}
	return arguments
}

func extractText(content json.RawMessage) string {
	var parsed struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(content, &parsed); err != nil {
		return ""
	}
	if parsed.Type == "text" {
		return parsed.Text
	}
	return ""
}

func scanText(text, promptName string) (auditor.Finding, bool) {
	if text == "" {
		return auditor.Finding{}, false
	}
	lowered := strings.ToLower(text)
	for _, keyword := range roleManipulation {
		if strings.Contains(lowered, keyword) {
			return poisoningFinding(promptName, keyword, "role manipulation"), true
		}
	}
	for _, keyword := range exfiltrationKeywords {
		if strings.Contains(lowered, keyword) {
			return exfilFinding(promptName, keyword, text), true
		}
	}
	return auditor.Finding{}, false
}

func poisoningFinding(promptName, keyword, category string) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityHigh,
		RuleID:      ruleID,
		TargetTool:  promptName,
		ParamPath:   "prompts/list",
		Description: fmt.Sprintf("Prompt template contains adversarial instruction %q (%s)", keyword, category),
		Remediation: "Remove instruction-overriding or role-manipulating text from prompt templates. Prompts must be informational, never instruct the LLM to hide actions from the user.",
	}
}

func exfilFinding(promptName, keyword, sample string) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityCritical,
		RuleID:      ruleID,
		TargetTool:  promptName,
		ParamPath:   "prompts/list",
		Description: fmt.Sprintf("Prompt template contains exfiltration directive %q", keyword),
		Remediation: "Remove URLs, webhooks and upload instructions from prompt templates. Prompts must never direct data toward external endpoints.",
		Evidence:    fmt.Sprintf("sample: %q", truncate(sample, 160)),
	}
}

func dedupe(findings []auditor.Finding) []auditor.Finding {
	var unique []auditor.Finding
	for _, finding := range findings {
		duplicate := false
		for _, existing := range unique {
			if existing.Description == finding.Description {
				duplicate = true
				break
			}
		}
		if !duplicate {
			unique = append(unique, finding)
		}
	}
	return unique
}

func truncate(text string, max int) string {
	if len(text) <= max {
		return text
	}
	return text[:max] + "..."
}
