package schema

import (
	"fmt"
	"strings"
)

type ValidationError struct {
	Path    string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation failed at %s: %s", e.Path, e.Message)
}

func ValidateTool(tool Tool) []ValidationError {
	var errors []ValidationError

	if tool.Name == "" {
		errors = append(errors, ValidationError{Path: "name", Message: "tool name is required"})
	}

	if tool.InputSchema.Type != "object" {
		errors = append(errors, ValidationError{Path: "inputSchema.type", Message: "root schema type must be object"})
	}

	schemaErrors := validateSchema(tool.InputSchema, "inputSchema")
	errors = append(errors, schemaErrors...)

	return errors
}

func validateSchema(schema JSONSchema, path string) []ValidationError {
	var errors []ValidationError

	validTypes := map[string]bool{
		"string": true, "number": true, "integer": true, "object": true, "array": true, "boolean": true, "null": true,
	}

	if schema.Type != "" && !validTypes[schema.Type] {
		errors = append(errors, ValidationError{Path: path + ".type", Message: "invalid schema type"})
	}

	for key, prop := range schema.Properties {
		propPath := fmt.Sprintf("%s.properties[%s]", path, key)
		if prop.Type == "string" && strings.Contains(strings.ToLower(key), "path") && prop.Description == "" {
			errors = append(errors, ValidationError{Path: propPath, Message: "path parameter lacks description"})
		}
		errors = append(errors, validateSchema(prop, propPath)...)
	}

	if schema.Type == "array" && schema.Items != nil {
		errors = append(errors, validateSchema(*schema.Items, path+".items")...)
	}

	return errors
}
