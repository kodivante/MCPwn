package fuzzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validDSL = `# custom payloads
payload "custom_echo" {
    rule = CmdInjection01
    template = "echo mcpwn_probe_{uuid}"
    expect = "mcpwn_probe_{uuid}"
    description = "Confirms command execution with echo"
}

payload "custom_timing" {
    rule = CmdInjection01
    template = "sleep 2"
    delay = 2s
}
`

const dslWithCommentedDeny = `payload "evil" {
    rule = CmdInjection01
    template = "curl http://evil.test"
}
`

func TestParseDSLValid(t *testing.T) {
	payloads, err := ParseDSL([]byte(validDSL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(payloads) != 2 {
		t.Fatalf("expected 2 payloads, got %d", len(payloads))
	}
	first := payloads[0]
	if first.Name != "custom_echo" || first.RuleID != "CmdInjection01" {
		t.Errorf("unexpected first payload: %+v", first)
	}
	if first.Template != "echo mcpwn_probe_{uuid}" || first.Expect != "mcpwn_probe_{uuid}" {
		t.Errorf("unexpected first payload fields: %+v", first)
	}
	if payloads[1].MinDelay != 2*time.Second {
		t.Errorf("expected 2s delay, got %s", payloads[1].MinDelay)
	}
}

func TestParseDSLErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{name: "missing rule", content: "payload \"x\" {\n    template = \"echo hi\"\n}"},
		{name: "missing template", content: "payload \"x\" {\n    rule = CmdInjection01\n}"},
		{name: "unknown field", content: "payload \"x\" {\n    rule = CmdInjection01\n    template = \"echo hi\"\n    bogus = value\n}"},
		{name: "unterminated block", content: "payload \"x\" {\n    rule = CmdInjection01"},
		{name: "content outside block", content: "template = \"echo hi\""},
		{name: "invalid delay", content: "payload \"x\" {\n    rule = CmdInjection01\n    template = \"sleep 1\"\n    delay = soon\n}"},
		{name: "invalid header", content: "payload x {\n    rule = CmdInjection01\n    template = \"echo hi\"\n}"},
		{name: "empty name", content: "payload \"\" {\n    rule = CmdInjection01\n    template = \"echo hi\"\n}"},
		{name: "unexpected brace", content: "}"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseDSL([]byte(tc.content)); err == nil {
				t.Error("expected dsl parsing error")
			}
		})
	}
}

func TestLoadPayloadFilesFromDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "custom.mcpwn"), []byte(validDSL), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "evil.mcpwn"), []byte(dslWithCommentedDeny), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "notes.txt"), []byte("ignored"), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := LoadPayloadFiles(directory)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Payloads) != 2 {
		t.Fatalf("expected 2 loaded payloads, got %d", len(result.Payloads))
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "rejected") {
		t.Errorf("expected 1 deny-list warning, got %v", result.Warnings)
	}
}

func TestLoadPayloadFilesSingleFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.mcpwn")
	if err := os.WriteFile(path, []byte(validDSL), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := LoadPayloadFiles(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Payloads) != 2 {
		t.Fatalf("expected 2 payloads, got %d", len(result.Payloads))
	}
}

func TestLoadPayloadFilesWrongExtension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.txt")
	if err := os.WriteFile(path, []byte(validDSL), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := LoadPayloadFiles(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Payloads) != 0 {
		t.Errorf("expected 0 payloads, got %d", len(result.Payloads))
	}
	if len(result.Warnings) != 1 {
		t.Errorf("expected 1 extension warning, got %v", result.Warnings)
	}
}

func TestLoadPayloadFilesMissingPath(t *testing.T) {
	if _, err := LoadPayloadFiles(filepath.Join(t.TempDir(), "missing.mcpwn")); err == nil {
		t.Error("expected missing path error")
	}
}
