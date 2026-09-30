package sourcescan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

const (
	maxFiles     = 2000
	maxFileBytes = 1024 * 1024
)

type sinkPattern struct {
	ruleID     string
	severity   auditor.Severity
	pattern    *regexp.Regexp
	python     bool
	javascript bool
	excludes   []string
}

var sinkPatterns = []sinkPattern{
	{ruleID: "SourceExec01", severity: auditor.SeverityMedium, python: true, pattern: regexp.MustCompile(`(os\.system|subprocess\.(run|Popen|call|check_output)|\beval\s*\(|\bexec\s*\(|shell\s*=\s*True)`)},
	{ruleID: "SourceExec01", severity: auditor.SeverityMedium, javascript: true, pattern: regexp.MustCompile(`(child_process|execSync\s*\(|spawnSync\s*\(|\beval\s*\(|new\s+Function\s*\()`)},
	{ruleID: "SourceDeserialization01", severity: auditor.SeverityMedium, python: true, excludes: []string{"SafeLoader"}, pattern: regexp.MustCompile(`(pickle\.loads?\s*\(|yaml\.load\s*\(|marshal\.loads?\s*\()`)},
	{ruleID: "SourceDeserialization01", severity: auditor.SeverityMedium, javascript: true, pattern: regexp.MustCompile(`(node-serialize|deserialize\s*\(|unserialize\s*\()`)},
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-[A-Za-z0-9]{16,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*["'][A-Za-z0-9+/_-]{12,}["']`),
}

type scannedFile struct {
	path     string
	isPython bool
	isScript bool
}

func ScanTree(root string) ([]auditor.Finding, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("source root read failed: %w", err)
	}
	var findings []auditor.Finding
	visited := 0
	for _, entry := range entries {
		if visited > maxFiles {
			break
		}
		findings = append(findings, scanEntry(entry, root, &visited)...)
	}
	return findings, nil
}

func scanEntry(entry fs.DirEntry, root string, visited *int) []auditor.Finding {
	if strings.HasPrefix(entry.Name(), ".") {
		return nil
	}
	fullPath := filepath.Join(root, entry.Name())
	if entry.IsDir() {
		if isSkippedDir(entry.Name()) {
			return nil
		}
		inner, err := os.ReadDir(fullPath)
		if err != nil {
			return nil
		}
		var findings []auditor.Finding
		for _, child := range inner {
			if *visited > maxFiles {
				break
			}
			findings = append(findings, scanEntry(child, fullPath, visited)...)
		}
		return findings
	}
	*visited++
	target := scannedFile{path: fullPath}
	switch strings.ToLower(filepath.Ext(entry.Name())) {
	case ".py":
		target.isPython = true
	case ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs":
		target.isScript = true
	default:
		return nil
	}
	return scanFile(target)
}

func isSkippedDir(name string) bool {
	switch name {
	case "node_modules", "venv", ".venv", "env", "dist", "build", "vendor", "site-packages":
		return true
	default:
		return false
	}
}

func scanFile(target scannedFile) []auditor.Finding {
	info, err := os.Stat(target.path)
	if err != nil || info.Size() > maxFileBytes {
		return nil
	}
	data, err := os.ReadFile(target.path)
	if err != nil {
		return nil
	}
	var findings []auditor.Finding
	for lineNumber, line := range strings.Split(string(data), "\n") {
		findings = append(findings, scanLine(target, lineNumber+1, line)...)
	}
	return findings
}

func scanLine(target scannedFile, lineNumber int, line string) []auditor.Finding {
	var findings []auditor.Finding
	for _, sink := range sinkPatterns {
		if target.isPython && !sink.python {
			continue
		}
		if target.isScript && !sink.javascript {
			continue
		}
		if !sink.pattern.MatchString(line) || containsAnyText(line, sink.excludes) {
			continue
		}
		findings = append(findings, finding(sink.ruleID, sink.severity, target.path, lineNumber, line))
	}
	for _, secret := range secretPatterns {
		if secret.MatchString(line) {
			findings = append(findings, finding("SourceSecret01", auditor.SeverityHigh, target.path, lineNumber, line))
			break
		}
	}
	return findings
}

func finding(ruleID string, severity auditor.Severity, path string, lineNumber int, line string) auditor.Finding {
	return auditor.Finding{
		Severity:     severity,
		RuleID:       ruleID,
		TargetTool:   filepath.Base(path),
		ParamPath:    "source",
		Description:  fmt.Sprintf("Source pattern %s at %s:%d", ruleID, path, lineNumber),
		Remediation:  remediationFor(ruleID),
		Evidence:     fmt.Sprintf("%s:%d: %s", path, lineNumber, trimLine(line)),
		Verification: "static",
	}
}

func remediationFor(ruleID string) string {
	switch ruleID {
	case "SourceSecret01":
		return "Move the secret to an environment variable or a secrets manager and purge it from history."
	case "SourceDeserialization01":
		return "Replace unsafe deserializers with JSON or schema-validated decoding; never unpickle caller-supplied bytes."
	default:
		return "Trace whether MCP tool input reaches this sink; if it does, validate and restrict the input before execution."
	}
}

func trimLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) > 120 {
		return trimmed[:120] + "..."
	}
	return trimmed
}

func containsAnyText(line string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(line, marker) {
			return true
		}
	}
	return false
}
