package exhaustion

import (
	"fmt"
	"sort"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

const (
	defaultRequests          = 20
	defaultDegradationFactor = 4.0
	defaultDegradationFloor  = 500 * time.Millisecond
)

type ToolsLister interface {
	ListTools() ([]schema.Tool, error)
}

type Options struct {
	Requests          int
	DegradationFactor float64
	DegradationFloor  time.Duration
}

type Engine struct {
	lister  ToolsLister
	options Options
}

func NewEngine(lister ToolsLister, options Options) *Engine {
	if options.Requests <= 0 {
		options.Requests = defaultRequests
	}
	if options.DegradationFactor <= 0 {
		options.DegradationFactor = defaultDegradationFactor
	}
	if options.DegradationFloor <= 0 {
		options.DegradationFloor = defaultDegradationFloor
	}
	return &Engine{lister: lister, options: options}
}

func (e *Engine) Probe() []auditor.Finding {
	latencies := make([]time.Duration, 0, e.options.Requests)
	for call := 0; call < e.options.Requests; call++ {
		start := time.Now()
		if _, err := e.lister.ListTools(); err != nil {
			return []auditor.Finding{failureFinding(call+1, err)}
		}
		latencies = append(latencies, time.Since(start))
	}

	half := len(latencies) / 2
	firstMedian := median(latencies[:half])
	lastMedian := median(latencies[half:])

	if firstMedian == 0 {
		firstMedian = time.Millisecond
	}
	ratio := float64(lastMedian) / float64(firstMedian)
	if lastMedian >= e.options.DegradationFloor && ratio >= e.options.DegradationFactor {
		return []auditor.Finding{degradationFinding(e.options.Requests, firstMedian, lastMedian, ratio)}
	}
	return nil
}

func failureFinding(failedAt int, err error) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityMedium,
		RuleID:      "ResourceExhaustion01",
		TargetTool:  "server",
		ParamPath:   "load",
		Description: fmt.Sprintf("Server failed after %d rapid sequential requests", failedAt),
		Remediation: "Add rate limiting, request queuing and resource bounds so sustained load cannot take the server down.",
		Confirmed:   true,
		Evidence:    fmt.Sprintf("request %d failed with: %v", failedAt, err),
	}
}

func degradationFinding(requests int, firstMedian, lastMedian time.Duration, ratio float64) auditor.Finding {
	return auditor.Finding{
		Severity:    auditor.SeverityLow,
		RuleID:      "ResourceExhaustion01",
		TargetTool:  "server",
		ParamPath:   "load",
		Description: fmt.Sprintf("Response latency degraded %.1fx under sustained load", ratio),
		Remediation: "Profile resource usage under load and add back-pressure so latency stays stable for sustained clients.",
		Confirmed:   true,
		Evidence: fmt.Sprintf("median latency rose from %s to %s across %d rapid requests",
			firstMedian.Round(time.Millisecond), lastMedian.Round(time.Millisecond), requests),
	}
}

func median(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}
