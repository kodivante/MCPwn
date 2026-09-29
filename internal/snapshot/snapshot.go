package snapshot

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/capability"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

const (
	driftRuleID      = "ToolDrift01"
	behaviorRuleID   = "BehaviorDrift01"
	hashPrefixLength = 12
)

type ToolFingerprint struct {
	Name            string   `json:"name"`
	DescriptionHash string   `json:"descriptionHash"`
	SchemaHash      string   `json:"schemaHash"`
	Capabilities    []string `json:"capabilities"`
}

type Snapshot struct {
	CreatedAt time.Time         `json:"createdAt"`
	Tools     []ToolFingerprint `json:"tools"`
	Shapes    map[string]string `json:"shapes"`
}

type ToolCaller interface {
	CallTool(name string, arguments json.RawMessage) (json.RawMessage, error)
}

func Save(path string, tools []schema.Tool, profiles []capability.ToolCapability, shapes map[string]string) error {
	snapshot := Snapshot{
		CreatedAt: time.Now().UTC(),
		Tools:     fingerprints(tools, profiles),
		Shapes:    shapes,
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("snapshot serialization failed: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("snapshot write failed: %w", err)
	}
	return nil
}

func fingerprints(tools []schema.Tool, profiles []capability.ToolCapability) []ToolFingerprint {
	profileByTool := make(map[string]capability.ToolCapability)
	for _, profile := range profiles {
		profileByTool[profile.Tool] = profile
	}
	result := make([]ToolFingerprint, 0, len(tools))
	for _, tool := range tools {
		profile := profileByTool[tool.Name]
		result = append(result, ToolFingerprint{
			Name:            tool.Name,
			DescriptionHash: shortHash(tool.Description),
			SchemaHash:      shortHash(schemaDigest(tool.InputSchema)),
			Capabilities:    profile.Capabilities,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func Compare(path string, caller ToolCaller, tools []schema.Tool, profiles []capability.ToolCapability) ([]auditor.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("snapshot read failed: %w", err)
	}
	var saved Snapshot
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("snapshot parsing failed: %w", err)
	}
	current := fingerprints(tools, profiles)
	findings := compareFingerprints(saved.Tools, current)
	if caller != nil && len(saved.Shapes) > 0 {
		findings = append(findings, compareShapes(caller, tools, saved.Shapes)...)
	}
	return findings, nil
}

func compareFingerprints(saved []ToolFingerprint, current []ToolFingerprint) []auditor.Finding {
	savedByTool := make(map[string]ToolFingerprint)
	for _, entry := range saved {
		savedByTool[entry.Name] = entry
	}
	currentByTool := make(map[string]bool)
	var findings []auditor.Finding

	for _, entry := range current {
		currentByTool[entry.Name] = true
		previous, ok := savedByTool[entry.Name]
		if !ok {
			findings = append(findings, driftFinding(
				auditor.SeverityLow, entry.Name,
				"Tool appeared after the approved snapshot",
				fmt.Sprintf("tool %q is not part of the approved baseline", entry.Name)))
			continue
		}
		if previous.DescriptionHash != entry.DescriptionHash {
			findings = append(findings, driftFinding(
				auditor.SeverityHigh, entry.Name,
				"Tool description changed since the approved snapshot",
				fmt.Sprintf("description hash moved from %s to %s", previous.DescriptionHash, entry.DescriptionHash)))
		}
		if previous.SchemaHash != entry.SchemaHash {
			findings = append(findings, driftFinding(
				auditor.SeverityMedium, entry.Name,
				"Tool schema changed since the approved snapshot",
				fmt.Sprintf("schema hash moved from %s to %s", previous.SchemaHash, entry.SchemaHash)))
		}
	}
	for _, entry := range saved {
		if !currentByTool[entry.Name] {
			findings = append(findings, driftFinding(
				auditor.SeverityMedium, entry.Name,
				"Tool removed since the approved snapshot",
				fmt.Sprintf("tool %q from the baseline is no longer listed", entry.Name)))
		}
	}
	return findings
}

func compareShapes(caller ToolCaller, tools []schema.Tool, savedShapes map[string]string) []auditor.Finding {
	var findings []auditor.Finding
	for _, tool := range tools {
		saved, ok := savedShapes[tool.Name]
		if !ok {
			continue
		}
		arguments, err := benignArguments(tool)
		if err != nil {
			continue
		}
		response, err := caller.CallTool(tool.Name, arguments)
		if err != nil {
			continue
		}
		current := responseShapeHash(response)
		if current == "" || current == saved {
			continue
		}
		findings = append(findings, auditor.Finding{
			Severity:    auditor.SeverityMedium,
			RuleID:      behaviorRuleID,
			TargetTool:  tool.Name,
			ParamPath:   "behavior",
			Description: "Tool response structure changed since the approved snapshot",
			Remediation: "Review the tool implementation: structural response changes after approval can indicate rug pulls or repurposed tools.",
			Confirmed:   true,
			Evidence:    fmt.Sprintf("response shape hash moved from %s to %s", saved, current),
		})
	}
	return findings
}

func driftFinding(severity auditor.Severity, tool, description, evidence string) auditor.Finding {
	return auditor.Finding{
		Severity:    severity,
		RuleID:      driftRuleID,
		TargetTool:  tool,
		ParamPath:   "fingerprint",
		Description: description,
		Remediation: "Re-approve the tool through your review workflow before agents keep calling it; freeze approved tools with signed baselines.",
		Evidence:    evidence,
	}
}

func benignArguments(tool schema.Tool) (json.RawMessage, error) {
	values := make(map[string]string)
	for key, prop := range tool.InputSchema.Properties {
		if prop.Type == "string" {
			values[key] = "mcpwnSnapshotValue"
		}
	}
	return json.Marshal(values)
}

func schemaDigest(inputSchema schema.JSONSchema) string {
	data, err := json.Marshal(inputSchema)
	if err != nil {
		return ""
	}
	return string(data)
}

func shortHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return fmt.Sprintf("%x", sum)[:hashPrefixLength]
}

func responseShapeHash(raw json.RawMessage) string {
	keys := shapeKeys(raw)
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	return shortHash(strings.Join(keys, "\n"))
}
