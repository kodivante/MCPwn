package sourcescan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

func writeSourceTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("dir creation failed: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("source write failed: %v", err)
		}
	}
	return root
}

func countRule(findings []auditor.Finding, ruleID string) int {
	count := 0
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			count++
		}
	}
	return count
}

func TestScanTreeDetectsPythonSinks(t *testing.T) {
	root := writeSourceTree(t, map[string]string{
		"server.py": "import os\nimport subprocess\n\ndef run(cmd):\n    os.system(cmd)\n    subprocess.run(cmd, shell=True)\n",
	})
	findings, err := ScanTree(root)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if countRule(findings, "SourceExec01") < 2 {
		t.Errorf("expected exec sink findings, got %+v", findings)
	}
	for _, finding := range findings {
		if finding.RuleID == "SourceExec01" && finding.TargetTool != "server.py" {
			t.Errorf("expected target server.py, got %s", finding.TargetTool)
		}
	}
}

func TestScanTreeDetectsDeserialization(t *testing.T) {
	root := writeSourceTree(t, map[string]string{
		"state.py": "import pickle\n\ndef load(data):\n    return pickle.loads(data)\n",
	})
	findings, err := ScanTree(root)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if countRule(findings, "SourceDeserialization01") != 1 {
		t.Errorf("expected 1 deserialization finding, got %+v", findings)
	}
}

func TestScanTreeSkipsSafeYaml(t *testing.T) {
	root := writeSourceTree(t, map[string]string{
		"conf.py": "import yaml\n\ndef load(data):\n    return yaml.load(data, Loader=yaml.SafeLoader)\n",
	})
	findings, err := ScanTree(root)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if countRule(findings, "SourceDeserialization01") != 0 {
		t.Errorf("SafeLoader must not be flagged, got %+v", findings)
	}
}

func TestScanTreeDetectsSecrets(t *testing.T) {
	root := writeSourceTree(t, map[string]string{
		"config.js": "const apiKey = \"sk-abcdefghijklmnopqrst\";\n",
	})
	findings, err := ScanTree(root)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	secrets := countRule(findings, "SourceSecret01")
	if secrets != 1 {
		t.Fatalf("expected 1 secret finding, got %+v", findings)
	}
	for _, finding := range findings {
		if finding.RuleID == "SourceSecret01" && finding.Severity != auditor.SeverityHigh {
			t.Errorf("secret must be HIGH, got %s", finding.Severity)
		}
	}
}

func TestScanTreeSkipsVendoredDirs(t *testing.T) {
	root := writeSourceTree(t, map[string]string{
		"node_modules/evil/index.js": "const cp = require('child_process');\n",
		"app/index.js":               "const cp = require('child_process');\n",
	})
	findings, err := ScanTree(root)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if countRule(findings, "SourceExec01") != 1 {
		t.Fatalf("expected only app findings, got %+v", findings)
	}
}

func TestScanTreeIgnoresOtherExtensions(t *testing.T) {
	root := writeSourceTree(t, map[string]string{
		"notes.md":  "os.system(rm -rf)",
		"image.png": "os.system",
	})
	findings, err := ScanTree(root)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings on non-source files, got %+v", findings)
	}
}

func TestScanTreeMissingRoot(t *testing.T) {
	if _, err := ScanTree(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("expected error scanning missing root")
	}
}
