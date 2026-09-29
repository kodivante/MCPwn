package rugpull

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/client"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

const (
	defaultTimeout = 10 * time.Second
	readWindow     = 3 * time.Second
	settleDelay    = 500 * time.Millisecond
)

type TransportSource func() (client.Transport, error)

type Options struct {
	Timeout time.Duration
}

type Engine struct {
	source  TransportSource
	timeout time.Duration
}

func NewEngine(source TransportSource, options Options) *Engine {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Engine{source: source, timeout: timeout}
}

func (e *Engine) Probe() []auditor.Finding {
	transport, err := e.source()
	if err != nil {
		return nil
	}
	defer transport.Close()

	session := client.NewSession(transport)
	if err := session.Initialize(); err != nil {
		return nil
	}

	firstListing, err := session.ListTools()
	if err != nil {
		return nil
	}
	firstSnapshot := snapshotTools(firstListing)

	time.Sleep(settleDelay)

	secondListing, err := session.ListTools()
	if err != nil {
		return nil
	}
	secondSnapshot := snapshotTools(secondListing)

	return compareSnapshots(firstSnapshot, secondSnapshot)
}

func snapshotTools(tools []schema.Tool) map[string]schema.Tool {
	snapshot := make(map[string]schema.Tool, len(tools))
	for _, tool := range tools {
		snapshot[tool.Name] = tool
	}
	return snapshot
}

func compareSnapshots(first, second map[string]schema.Tool) []auditor.Finding {
	var findings []auditor.Finding
	for name, before := range first {
		after, exists := second[name]
		if !exists {
			findings = append(findings, removalFinding(name, before.Description))
			continue
		}
		if before.Description != after.Description {
			findings = append(findings, changedFinding(name, before.Description, after.Description))
		}
	}
	for name := range second {
		if _, exists := first[name]; !exists {
			findings = append(findings, additionFinding(name, second[name].Description))
		}
	}
	return findings
}

func changedFinding(name, before, after string) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityHigh,
		RuleID:      "ToolRugPull01",
		TargetTool:  name,
		ParamPath:   "description",
		Description: fmt.Sprintf("Tool description changed after first listing: %q became %q", before, after),
		Remediation: "Pin tool descriptions server-side. Description changes mid-session enable rug-pull attacks against LLM agents.",
		Confirmed:   true,
		Evidence: fmt.Sprintf("before: %q after: %q (observed on second tools/list)",
			before, after),
	}
}

func removalFinding(name, description string) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityMedium,
		RuleID:      "ToolRugPull01",
		TargetTool:  name,
		ParamPath:   "description",
		Description: fmt.Sprintf("Tool %q disappeared from listing after first call (description was: %q)", name, description),
		Remediation: "Keep tool listings stable within a session. Removing tools mid-session breaks agent contracts and may mask malicious behavior.",
		Confirmed:   true,
		Evidence:    fmt.Sprintf("present in first listing, absent in second (was: %q)", description),
	}
}

func additionFinding(name, description string) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityMedium,
		RuleID:      "ToolRugPull01",
		TargetTool:  name,
		ParamPath:   "description",
		Description: fmt.Sprintf("Tool %q appeared mid-session (description: %q)", name, description),
		Remediation: "Keep tool listings stable within a session. Injecting tools mid-session is a rug-pull vector against agents that already made authorization decisions.",
		Confirmed:   true,
		Evidence:    fmt.Sprintf("absent in first listing, present in second (is: %q)", description),
	}
}

type readOutcome struct {
	msg client.JSONRPCMessage
	err error
}

func rawID(id int) json.RawMessage {
	return json.RawMessage(strconv.Itoa(id))
}
