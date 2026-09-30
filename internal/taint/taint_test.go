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

func TestImportAliasResolution(t *testing.T) {
	source := `
class _Registry:
    def tool(self, fn=None):
        if fn is None:
            return lambda handler: handler
        return fn

mcp = _Registry()
import subprocess as sp
from os import system as raw

@mcp.tool()
def launch(cmd):
    return sp.check_output(cmd, shell=True)

@mcp.tool()
def legacy(cmd):
    return raw(cmd)
`
	findings, _, err := Analyze(writeTree(t, map[string]string{"aliases.py": source}))
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected both alias-resolved findings, got %+v", findings)
	}
	for _, finding := range findings {
		if !strings.Contains(finding.Evidence, "subprocess.check_output") && !strings.Contains(finding.Evidence, "os.system") {
			t.Errorf("expected canonical sink names after alias resolution, got: %s", finding.Evidence)
		}
	}
}

func TestFromImportBareCallResolution(t *testing.T) {
	source := `
class _Registry:
    def tool(self, fn=None):
        if fn is None:
            return lambda handler: handler
        return fn

mcp = _Registry()
from subprocess import check_output

@mcp.tool()
def run(cmd):
    return check_output(cmd)
`
	findings, _, err := Analyze(writeTree(t, map[string]string{"fromimport.py": source}))
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0].Evidence, "subprocess.check_output") {
		t.Fatalf("expected from-import resolution, got %+v", findings)
	}
}

func TestClassMethodResolution(t *testing.T) {
	source := `
class _Registry:
    def tool(self, fn=None):
        if fn is None:
            return lambda handler: handler
        return fn

mcp = _Registry()

class Shell:
    def execute(self, command):
        return os.system(command)

@mcp.tool()
def run(cmd):
    shell = Shell()
    return shell.execute(cmd)
`
	findings, _, err := Analyze(writeTree(t, map[string]string{"classes.py": source}))
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 method-resolved finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Evidence, "Shell.execute") {
		t.Errorf("expected Shell.execute in path, got: %s", findings[0].Evidence)
	}
}

func TestFunctionAliasResolution(t *testing.T) {
	source := `
class _Registry:
    def tool(self, fn=None):
        if fn is None:
            return lambda handler: handler
        return fn

mcp = _Registry()

@mcp.tool()
def run(cmd):
    runner = os.system
    return runner(cmd)
`
	findings, _, err := Analyze(writeTree(t, map[string]string{"fnalias.py": source}))
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0].Evidence, "os.system") {
		t.Fatalf("expected function alias resolution to os.system, got %+v", findings)
	}
}

func TestSanitizerCleansesTaint(t *testing.T) {
	source := `
import shlex

class _Registry:
    def tool(self, fn=None):
        if fn is None:
            return lambda handler: handler
        return fn

mcp = _Registry()

@mcp.tool()
def run(cmd):
    safe = shlex.quote(cmd)
    return os.system("echo " + safe)
`
	findings, _, err := Analyze(writeTree(t, map[string]string{"sanitized.py": source}))
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("shlex.quote must cleanse the flow, got %+v", findings)
	}
}

func TestIntCastCleansesTaint(t *testing.T) {
	source := `
class _Registry:
    def tool(self, fn=None):
        if fn is None:
            return lambda handler: handler
        return fn

mcp = _Registry()

@mcp.tool()
def lookup(userId):
    clean = int(userId)
    return open("/records/" + str(clean)).read()
`
	findings, _, err := Analyze(writeTree(t, map[string]string{"casted.py": source}))
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("int cast must cleanse the flow, got %+v", findings)
	}
}

func TestAllowlistGuardCleansesTaint(t *testing.T) {
	source := `
ALLOWED = {"uptime", "date"}

class _Registry:
    def tool(self, fn=None):
        if fn is None:
            return lambda handler: handler
        return fn

mcp = _Registry()

@mcp.tool()
def run(cmd):
    if cmd not in ALLOWED:
        return "rejected"
    return os.system(cmd)
`
	findings, _, err := Analyze(writeTree(t, map[string]string{"guarded.py": source}))
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("allowlist guard must validate the flow, got %+v", findings)
	}
}

func TestPropertyTrackingAcrossSelf(t *testing.T) {
	source := `
class _Registry:
    def tool(self, fn=None):
        if fn is None:
            return lambda handler: handler
        return fn

mcp = _Registry()

class Runner:
    def prepare(self, command):
        self.cmd = command
        return self

    def fire(self):
        return os.system(self.cmd)

@mcp.tool()
def run(cmd):
    return Runner().prepare(cmd).fire()
`
	findings, _, err := Analyze(writeTree(t, map[string]string{"props.py": source}))
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected property-tracking finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Evidence, "Runner.fire") {
		t.Errorf("expected Runner.fire in path, got: %s", findings[0].Evidence)
	}
}

func TestFindingsMarkedStaticVerification(t *testing.T) {
	findings, _, err := Analyze("../../test/fixtures/lab/vulnerable")
	if err != nil {
		t.Fatalf("lab analyze failed: %v", err)
	}
	for _, finding := range findings {
		if finding.Verification != "static" {
			t.Errorf("taint findings must carry static verification, got %q", finding.Verification)
		}
	}
}

func TestJavaScriptRequireResolution(t *testing.T) {
	source := `
const cp = require('child_process');

server.tool("run", runHandler);

function runHandler(cmd) {
    return execViaCp(cmd);
}

function execViaCp(input) {
    return cp.execSync(input);
}
`
	findings, _, err := Analyze(writeTree(t, map[string]string{"runner.js": source}))
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 JS finding via require resolution, got %+v", findings)
	}
	if !strings.Contains(findings[0].Evidence, "execSync") {
		t.Errorf("expected execSync in path, got: %s", findings[0].Evidence)
	}
}
