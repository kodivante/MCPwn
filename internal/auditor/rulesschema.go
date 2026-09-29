package auditor

import (
	"fmt"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/schema"
)

var idorParamNames = []string{
	"userid", "accountid", "resourceid", "ownerid",
	"tenantid", "customerid", "orgid", "organizationid",
	"projectid", "groupid", "roleid",
}

type IdorRule struct{}

func (r *IdorRule) Evaluate(tool schema.Tool) []Finding {
	return evaluateSchema(tool, "inputSchema", tool.InputSchema, idorEval(tool))
}

func idorEval(tool schema.Tool) func(string, schema.JSONSchema) []Finding {
	return func(path string, prop schema.JSONSchema) []Finding {
		if prop.Type != "string" && prop.Type != "integer" && prop.Type != "number" {
			return nil
		}
		if len(prop.Enum) > 0 {
			return nil
		}
		key := strings.ToLower(extractKey(path))
		for _, name := range idorParamNames {
			if key == name || strings.HasSuffix(key, name) {
				return []Finding{{
					Severity:    SeverityHigh,
					RuleID:      "Idor01",
					TargetTool:  tool.Name,
					ParamPath:   path,
					Description: fmt.Sprintf("Parameter '%s' accepts user-supplied IDs without restriction, risking IDOR", extractKey(path)),
					Remediation: "Validate resource ownership server-side. Never trust client-supplied IDs without authorization checks.",
				}}
			}
		}
		return nil
	}
}

type MassAssignmentRule struct{}

func (r *MassAssignmentRule) Evaluate(tool schema.Tool) []Finding {
	return evaluateSchema(tool, "inputSchema", tool.InputSchema, massEval(tool))
}

func massEval(tool schema.Tool) func(string, schema.JSONSchema) []Finding {
	return func(path string, prop schema.JSONSchema) []Finding {
		if prop.Type != "object" || len(prop.Properties) == 0 {
			return nil
		}
		if prop.AdditionalProperties != nil && !*prop.AdditionalProperties {
			return nil
		}
		return []Finding{{
			Severity:    SeverityMedium,
			RuleID:      "MassAssignment01",
			TargetTool:  tool.Name,
			ParamPath:   path,
			Description: "Object schema allows additional properties, enabling mass assignment of undeclared fields",
			Remediation: "Set 'additionalProperties: false' in the JSON Schema to restrict inputs to declared fields only.",
		}}
	}
}

type WeakTypingRule struct{}

func (r *WeakTypingRule) Evaluate(tool schema.Tool) []Finding {
	return evaluateSchema(tool, "inputSchema", tool.InputSchema, weakTypingEval(tool))
}

func weakTypingEval(tool schema.Tool) func(string, schema.JSONSchema) []Finding {
	return func(path string, prop schema.JSONSchema) []Finding {
		if path == "inputSchema" {
			return nil
		}
		if prop.Type != "" || len(prop.Properties) > 0 || prop.Items != nil {
			return nil
		}
		key := extractKey(path)
		if key == "root" {
			return nil
		}
		return []Finding{{
			Severity:    SeverityLow,
			RuleID:      "WeakTyping01",
			TargetTool:  tool.Name,
			ParamPath:   path,
			Description: fmt.Sprintf("Parameter '%s' has no type defined, accepting any JSON value", key),
			Remediation: "Define an explicit 'type' for each parameter to enable proper input validation.",
		}}
	}
}

var criticalParamNames = []string{
	"id", "userid", "token", "key", "name", "command", "path", "url",
}

type MissingRequiredRule struct{}

func (r *MissingRequiredRule) Evaluate(tool schema.Tool) []Finding {
	required := make(map[string]bool, len(tool.InputSchema.Required))
	for _, req := range tool.InputSchema.Required {
		required[req] = true
	}
	var findings []Finding
	for key := range tool.InputSchema.Properties {
		findings = append(findings, missingRequiredFinding(tool, key, required)...)
	}
	return findings
}

func missingRequiredFinding(tool schema.Tool, key string, required map[string]bool) []Finding {
	if required[key] {
		return nil
	}
	lowKey := strings.ToLower(key)
	for _, name := range criticalParamNames {
		if lowKey == name || strings.Contains(lowKey, name) {
			return []Finding{{
				Severity:    SeverityLow,
				RuleID:      "MissingRequired01",
				TargetTool:  tool.Name,
				ParamPath:   "inputSchema.properties[" + key + "]",
				Description: fmt.Sprintf("Critical parameter '%s' is not in the required array", key),
				Remediation: "Add the parameter to 'required' if it is essential for the tool to function correctly.",
			}}
		}
	}
	return nil
}
