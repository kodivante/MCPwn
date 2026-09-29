package restraversal

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/client"
)

const (
	defaultTimeout = 10 * time.Second
	ruleID         = "ResourceTraversal01"
)

type Options struct {
	Timeout time.Duration
}

type Engine struct {
	session *client.Session
	timeout time.Duration
}

func NewEngine(session *client.Session, options Options) *Engine {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Engine{session: session, timeout: timeout}
}

func (e *Engine) Probe() []auditor.Finding {
	resources, err := e.session.ListResources()
	if err != nil {
		return nil
	}
	if len(resources) == 0 {
		return e.probeDirect()
	}
	return e.probeWithTemplate(resources)
}

func (e *Engine) probeDirect() []auditor.Finding {
	marker, directory, cleanup, err := createMarkerFile()
	if err != nil {
		return nil
	}
	defer cleanup()

	for _, payload := range traversalPayloads(directory) {
		if finding, ok := e.probeURI(payload, marker); ok {
			return []auditor.Finding{finding}
		}
	}
	return nil
}

func (e *Engine) probeWithTemplate(resources []client.Resource) []auditor.Finding {
	marker, directory, cleanup, err := createMarkerFile()
	if err != nil {
		return nil
	}
	defer cleanup()

	for _, resource := range resources {
		for _, payload := range traversalPayloads(directory) {
			probeURI := buildProbeURI(resource.URI, payload)
			if finding, ok := e.probeURI(probeURI, marker); ok {
				return []auditor.Finding{finding}
			}
		}
	}
	return nil
}

func (e *Engine) probeURI(uri, marker string) (auditor.Finding, bool) {
	result, err := e.readWithTimeout(uri)
	if err != nil {
		return auditor.Finding{}, false
	}
	for _, content := range result.Contents {
		if strings.Contains(string(content), marker) {
			return traversalFinding(uri, marker), true
		}
	}
	return auditor.Finding{}, false
}

func buildProbeURI(template, payload string) string {
	if strings.HasPrefix(payload, "/") || strings.HasPrefix(payload, "file:") {
		return payload
	}
	if idx := strings.LastIndex(template, "/"); idx >= 0 {
		return template[:idx+1] + payload
	}
	return payload
}

func traversalFinding(uri, marker string) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityHigh,
		RuleID:      ruleID,
		TargetTool:  "server",
		ParamPath:   "resources/read",
		Description: "Path traversal confirmed in resources/read: server returns files outside its resource root",
		Remediation: "Resolve resource URIs against a fixed base directory and reject any path containing traversal sequences or escaping the root.",
		Confirmed:   true,
		Evidence:    fmt.Sprintf("marker %q returned via resource URI %q", marker, uri),
	}
}

func createMarkerFile() (marker, directory string, cleanup func(), err error) {
	directory, err = os.MkdirTemp("", "mcpwnresource")
	if err != nil {
		return "", "", nil, fmt.Errorf("resource marker directory creation failed: %w", err)
	}
	marker = fmt.Sprintf("mcpwnResourceMarker%d", time.Now().UnixNano())
	content := []byte(marker)
	if err := os.WriteFile(filepath.Join(directory, "marker.txt"), content, 0600); err != nil {
		return "", "", nil, fmt.Errorf("resource marker file write failed: %w", err)
	}
	cleanup = func() {
		_ = os.RemoveAll(directory)
	}
	return marker, directory, cleanup, nil
}

func traversalPayloads(directory string) []string {
	relative := strings.TrimPrefix(directory, "/")
	return []string{
		filepath.Join(directory, "marker.txt"),
		"file://" + directory + "/marker.txt",
		"file:///" + directory + "/marker.txt",
		"../../../" + relative + "/marker.txt",
		"../../../../" + relative + "/marker.txt",
		"file://localhost" + directory + "/marker.txt",
	}
}

type readOutcome struct {
	result client.ReadResourceResult
	err    error
}

func (e *Engine) readWithTimeout(uri string) (client.ReadResourceResult, error) {
	outcome := make(chan readOutcome, 1)
	go func() {
		result, err := e.session.ReadResource(uri)
		outcome <- readOutcome{result: result, err: err}
	}()
	select {
	case res := <-outcome:
		return res.result, res.err
	case <-time.After(e.timeout):
		return client.ReadResourceResult{}, fmt.Errorf("resource read timed out after %s", e.timeout)
	}
}
