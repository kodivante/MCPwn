package taint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

func writeTree(t *testing.T, files map[string]string) string {
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

const vulnerablePython = `
class _Registry:
    def tool(self, fn):
        return fn

mcp = _Registry()

@mcp.tool()
def runReport(cmd):
    prepared = prepareShell(cmd)
    return executeShell(prepared)

def prepareShell(command):
    return command

def executeShell(command):
    outcome = os.system(command)
    return str(outcome)

@mcp.tool()
def fetchConfig(url):
    return downloadUrl(url)

def downloadUrl(target):
    return requests.get(target).text
`

const benignPython = `
class _Registry:
    def tool(self, fn):
        return fn

mcp = _Registry()

@mcp.tool()
def greet(name):
    return buildGreeting(name)

def buildGreeting(subject):
    return "hello " + subject

@mcp.tool()
def readManifest():
    with open("manifest.json") as handle:
        return handle.read()
`

func findingByPath(findings []auditor.Finding, path string) *auditor.Finding {
	for i := range findings {
		if findings[i].ParamPath == path {
			return &findings[i]
		}
	}
	return nil
}

func TestAnalyzeTracesInterproceduralPath(t *testing.T) {
	root := writeTree(t, map[string]string{"server.py": vulnerablePython})
	findings, paths, err := Analyze(root)
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}
	if len(paths) < 2 {
		t.Fatalf("expected at least 2 taint paths, got %+v", paths)
	}
	exec := findingByPath(findings, "taint:exec")
	if exec == nil {
		t.Fatalf("expected exec taint finding, got %+v", findings)
	}
	if exec.TargetTool != "runReport" || exec.RuleID != "SourceTaint01" {
		t.Errorf("unexpected finding shape: %+v", *exec)
	}
	if !strings.Contains(exec.Evidence, "runReport") || !strings.Contains(exec.Evidence, "executeShell") || !strings.Contains(exec.Evidence, "os.system") {
		t.Errorf("expected full call path in evidence, got: %s", exec.Evidence)
	}
	network := findingByPath(findings, "taint:network")
	if network == nil {
		t.Fatalf("expected network taint finding, got %+v", findings)
	}
	if !strings.Contains(network.Evidence, "fetchConfig") || !strings.Contains(network.Evidence, "downloadUrl") {
		t.Errorf("expected network path, got: %s", network.Evidence)
	}
}

func TestAnalyzeBenignYieldsNoFindings(t *testing.T) {
	root := writeTree(t, map[string]string{"server.py": benignPython})
	findings, paths, err := Analyze(root)
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}
	if len(findings) != 0 || len(paths) != 0 {
		t.Errorf("benign source must produce zero taint findings, got %+v paths=%+v", findings, paths)
	}
}

func TestAnalyzeConstantSinkArgumentsAreNotTainted(t *testing.T) {
	source := `
import os

def runFixed():
    return os.system("uptime")
`
	root := writeTree(t, map[string]string{"fixed.py": source})
	findings, _, err := Analyze(root)
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("constant sink arguments must not be flagged, got %+v", findings)
	}
}

func TestAnalyzeSurvivesRecursiveCalls(t *testing.T) {
	source := `
class _Registry:
    def tool(self, fn):
        return fn

mcp = _Registry()

@mcp.tool()
def loop(value):
    return loop(value)

@mcp.tool()
def boom(cmd):
    return os.system(cmd)
`
	root := writeTree(t, map[string]string{"loop.py": source})
	findings, _, err := Analyze(root)
	if err != nil {
		t.Fatalf("analyze failed on recursive source: %v", err)
	}
	if len(findings) != 1 || findings[0].TargetTool != "boom" {
		t.Errorf("expected single boom finding, got %+v", findings)
	}
}

func TestAnalyzeMissingRoot(t *testing.T) {
	if _, _, err := Analyze(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("expected error for missing root")
	}
}

func TestLabVulnerableCorpus(t *testing.T) {
	findings, paths, err := Analyze("../../test/fixtures/lab/vulnerable")
	if err != nil {
		t.Fatalf("lab analyze failed: %v", err)
	}
	if len(paths) < 2 {
		t.Fatalf("expected at least 2 lab paths, got %+v", paths)
	}
	exec := findingByPath(findings, "taint:exec")
	if exec == nil || exec.TargetTool != "runReport" {
		t.Fatalf("expected runReport exec taint, got %+v", findings)
	}
	if !strings.Contains(exec.Evidence, "executeShell") {
		t.Errorf("expected executeShell in path, got: %s", exec.Evidence)
	}
	network := findingByPath(findings, "taint:network")
	if network == nil || network.TargetTool != "fetchConfig" {
		t.Fatalf("expected fetchConfig network taint, got %+v", findings)
	}
	if !strings.Contains(network.Evidence, "downloadUrl") {
		t.Errorf("expected downloadUrl in path, got: %s", network.Evidence)
	}
}

func TestLabBenignCorpusIsClean(t *testing.T) {
	findings, paths, err := Analyze("../../test/fixtures/lab/benign")
	if err != nil {
		t.Fatalf("lab analyze failed: %v", err)
	}
	if len(findings) != 0 || len(paths) != 0 {
		t.Errorf("benign lab must yield zero taint output, got %+v paths=%+v", findings, paths)
	}
}
