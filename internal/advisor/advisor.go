package advisor

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/capability"
)

const (
	defaultTimeout     = 15 * time.Second
	hintRuleID         = "AdvisorHint01"
	maxHints           = 10
	hashLength         = 12
	advisoryConfidence = 40
)

type Options struct {
	Endpoint string
	Timeout  time.Duration
}

type Engine struct {
	endpoint string
	client   *http.Client
}

type advisoryRequest struct {
	Tools    []advisoryTool    `json:"tools"`
	Findings []advisoryFinding `json:"findings"`
}

type advisoryTool struct {
	Hash         string   `json:"hash"`
	Capabilities []string `json:"capabilities"`
}

type advisoryFinding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	ToolHash string `json:"toolHash"`
}

type advisoryResponse struct {
	Hypotheses []advisoryHypothesis `json:"hypotheses"`
}

type advisoryHypothesis struct {
	ToolHash string `json:"toolHash"`
	Probe    string `json:"probe"`
	Note     string `json:"note"`
}

func NewEngine(options Options) *Engine {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Engine{endpoint: options.Endpoint, client: &http.Client{Timeout: timeout}}
}

func (e *Engine) Consult(findings []auditor.Finding, profiles []capability.ToolCapability) ([]auditor.Finding, error) {
	if e.endpoint == "" {
		return nil, nil
	}
	hashByTool := make(map[string]string)
	tools := make([]advisoryTool, 0, len(profiles))
	for _, profile := range profiles {
		hash := toolHash(profile.Tool)
		hashByTool[hash] = profile.Tool
		tools = append(tools, advisoryTool{Hash: hash, Capabilities: profile.Capabilities})
	}

	advisoryFindings := make([]advisoryFinding, 0, len(findings))
	for _, finding := range findings {
		advisoryFindings = append(advisoryFindings, advisoryFinding{
			Rule:     finding.RuleID,
			Severity: string(finding.Severity),
			ToolHash: toolHash(finding.TargetTool),
		})
	}

	body, err := json.Marshal(advisoryRequest{Tools: tools, Findings: advisoryFindings})
	if err != nil {
		return nil, fmt.Errorf("advisor request serialization failed: %w", err)
	}
	resp, err := e.client.Post(e.endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("advisor consult failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("advisor returned status %d", resp.StatusCode)
	}
	var parsed advisoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("advisor response parsing failed: %w", err)
	}
	return e.hintFindings(parsed.Hypotheses, hashByTool), nil
}

func (e *Engine) hintFindings(hypotheses []advisoryHypothesis, hashByTool map[string]string) []auditor.Finding {
	var hints []auditor.Finding
	for _, hypothesis := range hypotheses {
		if len(hints) >= maxHints {
			break
		}
		tool, ok := hashByTool[hypothesis.ToolHash]
		if !ok || hypothesis.Probe == "" {
			continue
		}
		hints = append(hints, auditor.Finding{
			Severity:    auditor.SeverityLow,
			RuleID:      hintRuleID,
			TargetTool:  tool,
			ParamPath:   "advisor",
			Description: fmt.Sprintf("Advisory hypothesis: %s", hypothesis.Probe),
			Remediation: "Treat this as a lead, not a verdict: reproduce with the suggested probe before acting on it.",
			Evidence:    fmt.Sprintf("advisor hypothesis (unverified): %s", truncate(hypothesis.Note, 120)),
			Confidence:  advisoryConfidence,
		})
	}
	return hints
}

func toolHash(name string) string {
	sum := sha256.Sum256([]byte(name))
	return fmt.Sprintf("%x", sum)[:hashLength]
}

func truncate(text string, max int) string {
	if len(text) <= max {
		return text
	}
	return text[:max] + "..."
}
