package exhaustion

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

type stubLister struct {
	calls  int
	delay  func(call int) time.Duration
	failAt int
}

func (s *stubLister) ListTools() ([]schema.Tool, error) {
	s.calls++
	if s.failAt > 0 && s.calls >= s.failAt {
		return nil, errors.New("server overloaded")
	}
	if s.delay != nil {
		time.Sleep(s.delay(s.calls))
	}
	return []schema.Tool{{Name: "tool"}}, nil
}

func TestProbeStableServer(t *testing.T) {
	lister := &stubLister{delay: func(call int) time.Duration { return time.Millisecond }}
	engine := NewEngine(lister, Options{DegradationFloor: 50 * time.Millisecond})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings against stable server, got %d: %+v", len(findings), findings)
	}
	if lister.calls != defaultRequests {
		t.Errorf("expected %d requests, got %d", defaultRequests, lister.calls)
	}
}

func TestProbeDegradingServer(t *testing.T) {
	lister := &stubLister{delay: func(call int) time.Duration {
		if call <= 10 {
			return 2 * time.Millisecond
		}
		return 80 * time.Millisecond
	}}
	engine := NewEngine(lister, Options{DegradationFloor: 50 * time.Millisecond})
	findings := engine.Probe()
	if len(findings) != 1 {
		t.Fatalf("expected 1 degradation finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].RuleID != "ResourceExhaustion01" {
		t.Errorf("unexpected rule id %s", findings[0].RuleID)
	}
	if findings[0].Severity != auditor.SeverityLow {
		t.Errorf("expected LOW severity, got %s", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Evidence, "median latency rose") {
		t.Errorf("expected latency evidence, got %s", findings[0].Evidence)
	}
}

func TestProbeFailingServer(t *testing.T) {
	lister := &stubLister{failAt: 15}
	engine := NewEngine(lister, Options{})
	findings := engine.Probe()
	if len(findings) != 1 {
		t.Fatalf("expected 1 failure finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != auditor.SeverityMedium {
		t.Errorf("expected MEDIUM severity, got %s", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Description, "failed after 15") {
		t.Errorf("expected failure description, got %s", findings[0].Description)
	}
}

func TestProbeIgnoresTinyAbsoluteDegradation(t *testing.T) {
	lister := &stubLister{delay: func(call int) time.Duration {
		if call <= 10 {
			return time.Millisecond
		}
		return 20 * time.Millisecond
	}}
	engine := NewEngine(lister, Options{DegradationFloor: 500 * time.Millisecond})
	if findings := engine.Probe(); len(findings) != 0 {
		t.Errorf("expected 0 findings for tiny absolute degradation, got %d", len(findings))
	}
}

func TestMedian(t *testing.T) {
	tests := []struct {
		name   string
		values []time.Duration
		want   time.Duration
	}{
		{name: "odd count", values: []time.Duration{3, 1, 2}, want: 2},
		{name: "even count", values: []time.Duration{4, 1, 3, 2}, want: 2},
		{name: "empty", values: nil, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := median(tc.values); got != tc.want {
				t.Errorf("expected %s, got %s", tc.want, got)
			}
		})
	}
}
