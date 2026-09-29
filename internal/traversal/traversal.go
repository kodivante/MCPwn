package traversal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

const defaultTimeout = 10 * time.Second

const traversalRuleID = "PathTraversal01"

type ToolCaller interface {
	CallTool(name string, arguments json.RawMessage) (json.RawMessage, error)
}

type Options struct {
	Timeout time.Duration
}

type Engine struct {
	caller  ToolCaller
	timeout time.Duration
}

func NewEngine(caller ToolCaller, options Options) *Engine {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Engine{caller: caller, timeout: timeout}
}

func (e *Engine) ConfirmFindings(findings []auditor.Finding) []auditor.Finding {
	results := make([]auditor.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.RuleID == traversalRuleID {
			finding = e.confirmFinding(finding)
		}
		results = append(results, finding)
	}
	return results
}

func (e *Engine) confirmFinding(finding auditor.Finding) auditor.Finding {
	key := argumentKey(finding.ParamPath)
	if key == "" {
		return finding
	}
	marker, directory, cleanup, err := createMarkerFile()
	if err != nil {
		return finding
	}
	defer cleanup()

	for _, payload := range traversalPayloads(directory, marker) {
		arguments, err := json.Marshal(map[string]string{key: payload})
		if err != nil {
			return finding
		}
		raw, timedOut, err := e.callWithTimeout(finding.TargetTool, arguments)
		if timedOut || err != nil {
			return finding
		}
		if strings.Contains(responseText(raw), marker) {
			finding.Confirmed = true
			finding.Evidence = fmt.Sprintf("marker file %q returned via traversal payload %q", marker, payload)
			return finding
		}
	}
	return finding
}

func traversalPayloads(directory, marker string) []string {
	relative := strings.TrimPrefix(directory, "/")
	payloads := []string{filepath.Join(directory, marker)}
	for depth := 2; depth <= 10; depth += 2 {
		payloads = append(payloads, strings.Repeat("../", depth)+relative+"/"+marker)
	}
	return payloads
}

func createMarkerFile() (string, string, func(), error) {
	file, err := os.CreateTemp("", "mcpwn_traversal_*")
	if err != nil {
		return "", "", nil, fmt.Errorf("traversal marker file creation failed: %w", err)
	}
	marker := filepath.Base(file.Name())
	if _, err := file.WriteString(marker); err != nil {
		file.Close()
		os.Remove(file.Name())
		return "", "", nil, fmt.Errorf("traversal marker file write failed: %w", err)
	}
	if err := file.Close(); err != nil {
		os.Remove(file.Name())
		return "", "", nil, fmt.Errorf("traversal marker file close failed: %w", err)
	}
	cleanup := func() { os.Remove(file.Name()) }
	return marker, os.TempDir(), cleanup, nil
}

func argumentKey(paramPath string) string {
	parts := strings.Split(paramPath, "[")
	if len(parts) < 2 {
		return ""
	}
	last := strings.TrimSuffix(parts[len(parts)-1], ".items")
	return strings.TrimRight(last, "]")
}

type probeOutcome struct {
	raw      json.RawMessage
	err      error
	timedOut bool
}

func (e *Engine) callWithTimeout(toolName string, arguments json.RawMessage) (json.RawMessage, bool, error) {
	outcome := make(chan probeOutcome, 1)
	go func() {
		raw, err := e.caller.CallTool(toolName, arguments)
		outcome <- probeOutcome{raw: raw, err: err}
	}()
	select {
	case res := <-outcome:
		return res.raw, false, res.err
	case <-time.After(e.timeout):
		return nil, true, fmt.Errorf("traversal probe timed out after %s", e.timeout)
	}
}

type probeContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type probeResponse struct {
	Content []probeContent `json:"content"`
	IsError bool           `json:"isError"`
}

func responseText(raw json.RawMessage) string {
	var resp probeResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return string(raw)
	}
	var builder strings.Builder
	for _, content := range resp.Content {
		if content.Type == "text" {
			builder.WriteString(content.Text)
		}
	}
	return builder.String()
}
