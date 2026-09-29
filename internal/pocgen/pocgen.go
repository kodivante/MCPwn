package pocgen

import (
	"fmt"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

type Options struct {
	Target   string
	Language string
}

type PoCFile struct {
	Name    string
	Content []byte
}

var pocForbiddenTokens = []string{
	"curl", "wget", "socket", "subprocess", "os.system",
	"rm -rf", "rm -", "mkfs", "/etc/passwd", "/etc/shadow",
	"reverse shell", "chmod", "chown", "sudo", "netcat",
}

func Generate(finding auditor.Finding, options Options) (PoCFile, error) {
	var content string
	var name string
	switch options.Language {
	case "", "python":
		name = fileName(finding, "py")
		content = renderTemplate(pythonTemplate, name, finding, options.Target)
	case "bash":
		name = fileName(finding, "sh")
		content = renderTemplate(bashTemplate, name, finding, options.Target)
	default:
		return PoCFile{}, fmt.Errorf("unsupported poc language %q", options.Language)
	}
	if err := ensureSafePoC(content); err != nil {
		return PoCFile{}, err
	}
	return PoCFile{Name: name, Content: []byte(content)}, nil
}

func renderTemplate(template, name string, finding auditor.Finding, target string) string {
	replacements := map[string]string{
		"{NAME}":        name,
		"{TOOL}":        finding.TargetTool,
		"{PARAM}":       paramKey(finding.ParamPath),
		"{RULEID}":      finding.RuleID,
		"{SEVERITY}":    string(finding.Severity),
		"{EVIDENCE}":    finding.Evidence,
		"{REMEDIATION}": finding.Remediation,
		"{TARGET}":      target,
	}
	content := template
	for placeholder, value := range replacements {
		content = strings.ReplaceAll(content, placeholder, value)
	}
	return content
}

func fileName(finding auditor.Finding, extension string) string {
	return finding.RuleID + "_" + sanitizeName(finding.TargetTool) + "." + extension
}

func sanitizeName(name string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(name) {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if isAlnum {
			builder.WriteRune(r)
			continue
		}
		builder.WriteByte('_')
	}
	return builder.String()
}

func paramKey(paramPath string) string {
	parts := strings.Split(paramPath, "[")
	if len(parts) < 2 {
		return "input"
	}
	last := strings.TrimSuffix(parts[len(parts)-1], ".items")
	key := strings.TrimRight(last, "]")
	if key == "" {
		return "input"
	}
	return key
}

func ensureSafePoC(content string) error {
	lowered := strings.ToLower(content)
	for _, token := range pocForbiddenTokens {
		if strings.Contains(lowered, token) {
			return fmt.Errorf("poc generation refused: content contains forbidden token %q", token)
		}
	}
	return nil
}
