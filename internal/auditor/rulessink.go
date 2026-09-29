package auditor

import (
	"fmt"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/schema"
)

type TemplateInjectionRule struct{}

func (r *TemplateInjectionRule) Evaluate(tool schema.Tool) []Finding {
	return evaluateSchema(tool, "inputSchema", tool.InputSchema, func(path string, prop schema.JSONSchema) []Finding {
		key := extractKey(path)
		context := strings.ToLower(key + " " + prop.Description + " " + tool.Description)
		if prop.Type != "string" || !strings.Contains(key, "template") {
			return nil
		}
		if !containsTemplateRender(context) {
			return nil
		}
		return []Finding{
			{
				Severity:    SeverityMedium,
				RuleID:      "TemplateInjection01",
				TargetTool:  tool.Name,
				ParamPath:   path,
				Description: fmt.Sprintf("Parameter '%s' feeds a template renderer, risk of server-side template injection", key),
				Remediation: "Use logic-less templates with auto-escaping, or sandbox the engine and never pass raw user input as template source.",
			},
		}
	})
}

func containsTemplateRender(context string) bool {
	for _, marker := range []string{"render", "jinja", "format", "template engine", "mustache", "handlebars"} {
		if strings.Contains(context, marker) {
			return true
		}
	}
	return false
}

type UnsafeDeserializationRule struct{}

func (r *UnsafeDeserializationRule) Evaluate(tool schema.Tool) []Finding {
	context := strings.ToLower(tool.Description)
	for key, prop := range tool.InputSchema.Properties {
		paramContext := strings.ToLower(key + " " + prop.Description)
		if !containsDeserialization(context) && !containsDeserialization(paramContext) {
			continue
		}
		return []Finding{
			{
				Severity:    SeverityHigh,
				RuleID:      "UnsafeDeserialization01",
				TargetTool:  tool.Name,
				ParamPath:   "inputSchema.properties[" + key + "]",
				Description: fmt.Sprintf("Tool '%s' advertises deserialization of caller-supplied data", tool.Name),
				Remediation: "Deserialize only safe formats (JSON) or enforce typed schemas; never pass raw bytes into pickle, yaml.load or language-native deserializers.",
			},
		}
	}
	return nil
}

func containsDeserialization(context string) bool {
	for _, marker := range []string{"deserialize", "deserializ", "unpickle", "yaml.load", "parse yaml", "decode binary", "pickle"} {
		if strings.Contains(context, marker) {
			return true
		}
	}
	return false
}

type PrototypePollutionRule struct{}

func (r *PrototypePollutionRule) Evaluate(tool schema.Tool) []Finding {
	return evaluateSchema(tool, "inputSchema", tool.InputSchema, func(path string, prop schema.JSONSchema) []Finding {
		key := extractKey(path)
		context := strings.ToLower(key + " " + prop.Description + " " + tool.Description)
		if prop.Type != "object" {
			return nil
		}
		if !containsMergeMarker(context) {
			return nil
		}
		return []Finding{
			{
				Severity:    SeverityMedium,
				RuleID:      "PrototypePollution01",
				TargetTool:  tool.Name,
				ParamPath:   path,
				Description: fmt.Sprintf("Parameter '%s' is merged into objects, risk of prototype pollution in JavaScript runtimes", key),
				Remediation: "Recursively strip __proto__, constructor and prototype keys before merging, and merge into fresh objects.",
			},
		}
	})
}

func containsMergeMarker(context string) bool {
	for _, marker := range []string{"merge", "extend", "deep clone", "deep copy", "assign", "inherit"} {
		if strings.Contains(context, marker) {
			return true
		}
	}
	return false
}

type NoSqlInjectionRule struct{}

func (r *NoSqlInjectionRule) Evaluate(tool schema.Tool) []Finding {
	return evaluateSchema(tool, "inputSchema", tool.InputSchema, func(path string, prop schema.JSONSchema) []Finding {
		key := extractKey(path)
		if prop.Type != "string" && prop.Type != "object" {
			return nil
		}
		keyContext := strings.ToLower(key)
		if !strings.Contains(keyContext, "query") && !strings.Contains(keyContext, "filter") && !strings.Contains(keyContext, "document") {
			return nil
		}
		context := strings.ToLower(prop.Description + " " + tool.Description)
		if !containsNoSqlMarker(context) {
			return nil
		}
		return []Finding{
			{
				Severity:    SeverityMedium,
				RuleID:      "NoSqlInjection01",
				TargetTool:  tool.Name,
				ParamPath:   path,
				Description: fmt.Sprintf("Parameter '%s' builds NoSQL queries, risk of operator injection ($ne, $where, $gt)", key),
				Remediation: "Validate query structure against an allowlist of operators and use typed query builders instead of raw documents.",
			},
		}
	})
}

func containsNoSqlMarker(context string) bool {
	for _, marker := range []string{"mongo", "nosql", "document db", "document database", "collection"} {
		if strings.Contains(context, marker) {
			return true
		}
	}
	return false
}
