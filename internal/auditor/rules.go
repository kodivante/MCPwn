package auditor

import (
	"fmt"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/schema"
)

type Rule interface {
	Evaluate(tool schema.Tool) []Finding
}

type CommandInjectionRule struct{}

func (r *CommandInjectionRule) Evaluate(tool schema.Tool) []Finding {
	return evaluateSchema(tool, "inputSchema", tool.InputSchema, func(path string, prop schema.JSONSchema) []Finding {
		key := extractKey(path)
		if prop.Type == "string" && (contains(key, "cmd") || contains(key, "command") || contains(key, "exec") || contains(key, "script")) {
			if len(prop.Enum) == 0 {
				return []Finding{
					{
						Severity:    SeverityCritical,
						RuleID:      "CmdInjection01",
						TargetTool:  tool.Name,
						ParamPath:   path,
						Description: fmt.Sprintf("Parameter '%s' allows raw command execution without enum restrictions", key),
						Remediation: "Use an 'enum' array to restrict the parameter to exactly the allowed commands instead of accepting any string.",
					},
				}
			}
		}
		return nil
	})
}

type PathTraversalRule struct{}

func (r *PathTraversalRule) Evaluate(tool schema.Tool) []Finding {
	return evaluateSchema(tool, "inputSchema", tool.InputSchema, func(path string, prop schema.JSONSchema) []Finding {
		key := extractKey(path)
		if prop.Type == "string" && (contains(key, "path") || contains(key, "file") || contains(key, "dir")) {
			return []Finding{
				{
					Severity:    SeverityHigh,
					RuleID:      "PathTraversal01",
					TargetTool:  tool.Name,
					ParamPath:   path,
					Description: fmt.Sprintf("Parameter '%s' operates on file paths, ensure sanitization against directory traversal", key),
					Remediation: "Ensure the server normalizes the path and verifies it resides within a safe root directory before operating on it.",
				},
			}
		}
		return nil
	})
}

type SSRFRule struct{}

func (r *SSRFRule) Evaluate(tool schema.Tool) []Finding {
	return evaluateSchema(tool, "inputSchema", tool.InputSchema, func(path string, prop schema.JSONSchema) []Finding {
		key := extractKey(path)
		if prop.Type == "string" && (contains(key, "url") || contains(key, "endpoint") || contains(key, "webhook")) {
			return []Finding{
				{
					Severity:    SeverityMedium,
					RuleID:      "Ssrf01",
					TargetTool:  tool.Name,
					ParamPath:   path,
					Description: fmt.Sprintf("Parameter '%s' accepts URLs, risk of Server-Side Request Forgery", key),
					Remediation: "Validate the URL protocol (e.g., allow only https://) and restrict the domain using an allowlist if possible.",
				},
			}
		}
		return nil
	})
}

type CredentialsLeakRule struct{}

func (r *CredentialsLeakRule) Evaluate(tool schema.Tool) []Finding {
	return evaluateSchema(tool, "inputSchema", tool.InputSchema, func(path string, prop schema.JSONSchema) []Finding {
		key := extractKey(path)
		if prop.Type == "string" && (contains(key, "token") || contains(key, "apikey") || contains(key, "secret") || contains(key, "password")) {
			return []Finding{
				{
					Severity:    SeverityCritical,
					RuleID:      "CredentialsLeak01",
					TargetTool:  tool.Name,
					ParamPath:   path,
					Description: fmt.Sprintf("Parameter '%s' appears to ask for raw credentials from the LLM", key),
					Remediation: "Never pass raw credentials as parameters. The MCP server should load credentials securely from its own environment variables or secrets manager.",
				},
			}
		}
		return nil
	})
}

type SQLInjectionRule struct{}

func (r *SQLInjectionRule) Evaluate(tool schema.Tool) []Finding {
	return evaluateSchema(tool, "inputSchema", tool.InputSchema, func(path string, prop schema.JSONSchema) []Finding {
		key := extractKey(path)
		if prop.Type == "string" && (contains(key, "query") || contains(key, "sql") || contains(key, "db")) {
			return []Finding{
				{
					Severity:    SeverityHigh,
					RuleID:      "SqlInjection01",
					TargetTool:  tool.Name,
					ParamPath:   path,
					Description: fmt.Sprintf("Parameter '%s' accepts queries directly, risking SQL injection", key),
					Remediation: "Refactor the tool to accept specific parameters (e.g., 'userId') and use parameterized queries internally, rather than accepting raw SQL strings.",
				},
			}
		}
		return nil
	})
}

type DosRule struct{}

func (r *DosRule) Evaluate(tool schema.Tool) []Finding {
	if contains(tool.Name, "readfile") || contains(tool.Name, "read_file") {
		hasLimit := false
		evaluateSchema(tool, "inputSchema", tool.InputSchema, func(path string, prop schema.JSONSchema) []Finding {
			key := extractKey(path)
			if contains(key, "limit") || contains(key, "max") || contains(key, "lines") {
				hasLimit = true
			}
			return nil
		})

		if !hasLimit {
			return []Finding{
				{
					Severity:    SeverityMedium,
					RuleID:      "Dos01",
					TargetTool:  tool.Name,
					ParamPath:   "root",
					Description: "File reading tool lacks bounding parameters (e.g., 'limit' or 'maxLines'), risking Denial of Service by reading massive files",
					Remediation: "Add a 'maxLines' or 'limit' parameter to the schema and enforce pagination or byte-limits in the server logic.",
				},
			}
		}
	}
	return nil
}

type StateMutationRule struct{}

func (r *StateMutationRule) Evaluate(tool schema.Tool) []Finding {
	if contains(tool.Name, "delete") || contains(tool.Name, "drop") || contains(tool.Name, "update") || contains(tool.Name, "write") {
		hasConfirmation := false
		evaluateSchema(tool, "inputSchema", tool.InputSchema, func(path string, prop schema.JSONSchema) []Finding {
			key := extractKey(path)
			if contains(key, "confirm") || contains(key, "approve") {
				hasConfirmation = true
			}
			return nil
		})

		if !hasConfirmation {
			return []Finding{
				{
					Severity:    SeverityHigh,
					RuleID:      "StateMutation01",
					TargetTool:  tool.Name,
					ParamPath:   "root",
					Description: "Tool mutates state (delete/update) but lacks a confirmation parameter, risking unauthorized autonomous actions",
					Remediation: "Add a boolean 'confirm' parameter and implement Human-In-The-Loop (HITL) approval on the client side before calling this tool.",
				},
			}
		}
	}
	return nil
}

type PromptInjectionRule struct{}

func (r *PromptInjectionRule) Evaluate(tool schema.Tool) []Finding {
	return evaluateSchema(tool, "inputSchema", tool.InputSchema, func(path string, prop schema.JSONSchema) []Finding {
		key := extractKey(path)
		if prop.Type == "string" && (contains(key, "prompt") || contains(key, "instruction") || contains(key, "message")) {
			return []Finding{
				{
					Severity:    SeverityMedium,
					RuleID:      "PromptInjection01",
					TargetTool:  tool.Name,
					ParamPath:   path,
					Description: fmt.Sprintf("Parameter '%s' feeds user-controlled text into the model, a potential prompt injection sink", key),
					Remediation: "Delimit and validate user input server-side and keep it separated from system instructions.",
				},
			}
		}
		return nil
	})
}

func evaluateSchema(tool schema.Tool, path string, s schema.JSONSchema, evaluator func(string, schema.JSONSchema) []Finding) []Finding {
	var findings []Finding
	findings = append(findings, evaluator(path, s)...)

	for key, prop := range s.Properties {
		propPath := fmt.Sprintf("%s.properties[%s]", path, key)
		findings = append(findings, evaluateSchema(tool, propPath, prop, evaluator)...)
	}

	if s.Type == "array" && s.Items != nil {
		findings = append(findings, evaluateSchema(tool, path+".items", *s.Items, evaluator)...)
	}

	return findings
}

func extractKey(path string) string {
	parts := strings.Split(path, "[")
	if len(parts) > 1 {
		last := parts[len(parts)-1]
		return strings.TrimRight(last, "]")
	}
	return "root"
}

func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), substr)
}
