package ssrfcanary

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

const (
	defaultTimeout = 10 * time.Second
	callbackWindow = 2 * time.Second
	callbackPoll   = 100 * time.Millisecond
)

const ssrfRuleID = "Ssrf01"

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
	hasTarget := false
	for _, finding := range findings {
		if finding.RuleID == ssrfRuleID {
			hasTarget = true
			break
		}
	}
	if !hasTarget {
		return findings
	}
	canary, err := startCanary()
	if err != nil {
		return findings
	}
	defer canary.stop()

	results := make([]auditor.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.RuleID == ssrfRuleID {
			finding = e.confirmFinding(finding, canary)
		}
		results = append(results, finding)
	}
	return results
}

func (e *Engine) confirmFinding(finding auditor.Finding, canary *canaryServer) auditor.Finding {
	key := argumentKey(finding.ParamPath)
	if key == "" {
		return finding
	}
	canary.reset()

	arguments, err := json.Marshal(map[string]string{key: canary.url})
	if err != nil {
		return finding
	}
	e.callWithTimeout(finding.TargetTool, arguments)

	deadline := time.Now().Add(callbackWindow)
	for time.Now().Before(deadline) {
		if canary.wasHit() {
			finding.Confirmed = true
			finding.Evidence = fmt.Sprintf("server fetched local canary endpoint %q", canary.url)
			return finding
		}
		time.Sleep(callbackPoll)
	}
	return finding
}

type canaryServer struct {
	mu     sync.Mutex
	hit    bool
	server *http.Server
	url    string
}

func startCanary() (*canaryServer, error) {
	canary := &canaryServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/canary", func(w http.ResponseWriter, r *http.Request) {
		canary.mu.Lock()
		canary.hit = true
		canary.mu.Unlock()
		fmt.Fprint(w, "mcpwn canary")
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("canary listener creation failed: %w", err)
	}
	server := &http.Server{Handler: mux}
	go server.Serve(listener)

	port := listener.Addr().(*net.TCPAddr).Port
	canary.server = server
	canary.url = fmt.Sprintf("http://127.0.0.1:%d/canary", port)
	return canary, nil
}

func (c *canaryServer) wasHit() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hit
}

func (c *canaryServer) reset() {
	c.mu.Lock()
	c.hit = false
	c.mu.Unlock()
}

func (c *canaryServer) stop() error {
	return c.server.Close()
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
	raw json.RawMessage
	err error
}

func (e *Engine) callWithTimeout(toolName string, arguments json.RawMessage) (json.RawMessage, error) {
	outcome := make(chan probeOutcome, 1)
	go func() {
		raw, err := e.caller.CallTool(toolName, arguments)
		outcome <- probeOutcome{raw: raw, err: err}
	}()
	select {
	case res := <-outcome:
		return res.raw, res.err
	case <-time.After(e.timeout):
		return nil, fmt.Errorf("ssrf probe timed out after %s", e.timeout)
	}
}
