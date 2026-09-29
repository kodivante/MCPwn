package pocgen

import (
	"strings"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

func confirmedFinding() auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityCritical,
		RuleID:      "CmdInjection01",
		TargetTool:  "system_exec",
		ParamPath:   "inputSchema.properties[cmd]",
		Description: "raw command execution",
		Remediation: "Use an enum to restrict the command",
		Confirmed:   true,
		Evidence:    "marker mcpwn_probe found in tool response",
	}
}

func TestGeneratePythonHeader(t *testing.T) {
	poc, err := Generate(confirmedFinding(), Options{Target: "python3 server.py"})
	if err != nil {
		t.Fatal(err)
	}
	if poc.Name != "CmdInjection01_system_exec.py" {
		t.Errorf("unexpected poc name %s", poc.Name)
	}
	content := string(poc.Content)
	for _, want := range []string{
		"MCPwn Proof of Concept",
		"Authorized testing only",
		"Tool: system_exec",
		"Finding: CmdInjection01",
		"Severity: CRITICAL",
		"[+] PoC executed",
		"# Remediation: Use an enum to restrict the command",
		"python3 pocs/CmdInjection01_system_exec.py | python3 server.py",
		`{"cmd": "echo " + MARKER}`,
	} {
		if !strings.Contains(content, want) {
			t.Errorf("expected %q in poc content", want)
		}
	}
}

func TestGenerateBash(t *testing.T) {
	poc, err := Generate(confirmedFinding(), Options{Target: "python3 server.py", Language: "bash"})
	if err != nil {
		t.Fatal(err)
	}
	if poc.Name != "CmdInjection01_system_exec.sh" {
		t.Errorf("unexpected poc name %s", poc.Name)
	}
	content := string(poc.Content)
	for _, want := range []string{
		"#!/usr/bin/env bash",
		"[+] PoC executed",
		"# Remediation: Use an enum to restrict the command",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("expected %q in poc content", want)
		}
	}
}

func TestGenerateForbiddenTokensAbsent(t *testing.T) {
	for _, language := range []string{"python", "bash"} {
		t.Run(language, func(t *testing.T) {
			poc, err := Generate(confirmedFinding(), Options{Language: language})
			if err != nil {
				t.Fatal(err)
			}
			lowered := strings.ToLower(string(poc.Content))
			for _, token := range pocForbiddenTokens {
				if strings.Contains(lowered, token) {
					t.Errorf("poc contains forbidden token %q", token)
				}
			}
		})
	}
}

func TestGenerateRejectsHostileToolName(t *testing.T) {
	finding := confirmedFinding()
	finding.TargetTool = "curlFetcher"
	if _, err := Generate(finding, Options{}); err == nil {
		t.Error("expected safety rejection for hostile tool name")
	}
}

func TestGenerateUnknownLanguage(t *testing.T) {
	if _, err := Generate(confirmedFinding(), Options{Language: "ruby"}); err == nil {
		t.Error("expected unsupported language error")
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		name string
		tool string
		want string
	}{
		{name: "already clean", tool: "system_exec", want: "system_exec"},
		{name: "mixed case", tool: "readFile", want: "readfile"},
		{name: "spaces and dots", tool: "read file.v2", want: "read_file_v2"},
		{name: "slashes", tool: "a/b", want: "a_b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeName(tc.tool); got != tc.want {
				t.Errorf("expected %s, got %s", tc.want, got)
			}
		})
	}
}
