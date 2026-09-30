package campaign

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/capability"
)

const (
	StatusConfirmed = "confirmed"
	StatusUnproven  = "unproven"
)

type Hypothesis struct {
	RuleID     string `json:"ruleId"`
	TargetTool string `json:"tool,omitempty"`
	Probe      string `json:"probe"`
	Status     string `json:"status"`
}

var confirmableRules = map[string]string{
	"CmdInjection01":   "fuzzer",
	"PathTraversal01":  "traversal prober",
	"Ssrf01":           "ssrf canary",
	"MassAssignment01": "pollution probe",
	"TokenLeak01":      "token leak scan",
	"SqlInjection01":   "schema-aware fuzzing",
	"StateMutation01":  "exhaustion and race probes",
	"Idor01":           "schema-aware fuzzing",
	"ToolPoisoning01":  "prompt and description audit",
	"SourceTaint01":    "runtime confirmation probes",
	"ContextSharing01": "resource traversal probe",
}

var capabilityProbes = map[string]string{
	capability.Credentials: "token leak scan",
	capability.State:       "exhaustion and race probes",
	capability.Exec:        "dynamic fuzzer",
	capability.Network:     "ssrf canary",
}

var serverProbes = []Hypothesis{
	{RuleID: "StateDesync01", Probe: "lifecycle desync probes"},
	{RuleID: "ProtocolRobustness01", Probe: "protocol fuzzer"},
	{RuleID: "ToolRugPull01", Probe: "rug-pull re-listing"},
	{RuleID: "SamplingAbuse01", Probe: "sampling abuse probe"},
	{RuleID: "ElicitationAbuse01", Probe: "elicitation abuse probe"},
	{RuleID: "RootsProbe01", Probe: "client roots probe"},
	{RuleID: "HttpAuthBypass01", Probe: "http threat engine"},
}

func BuildHypotheses(findings []auditor.Finding, profiles []capability.ToolCapability) []Hypothesis {
	seen := make(map[string]bool)
	hypotheses := make([]Hypothesis, 0, len(findings)+len(profiles)+len(serverProbes))

	for _, finding := range findings {
		probe, ok := confirmableRules[finding.RuleID]
		if !ok || finding.Confirmed {
			continue
		}
		key := finding.RuleID + "|" + finding.TargetTool
		if seen[key] {
			continue
		}
		seen[key] = true
		hypotheses = append(hypotheses, Hypothesis{
			RuleID:     finding.RuleID,
			TargetTool: finding.TargetTool,
			Probe:      probe,
			Status:     StatusUnproven,
		})
	}

	for _, profile := range profiles {
		for _, capabilityName := range profile.Capabilities {
			probe, ok := capabilityProbes[capabilityName]
			if !ok {
				continue
			}
			key := capabilityName + "|" + profile.Tool
			if seen[key] {
				continue
			}
			seen[key] = true
			hypotheses = append(hypotheses, Hypothesis{
				RuleID:     capabilityName,
				TargetTool: profile.Tool,
				Probe:      probe,
				Status:     StatusUnproven,
			})
		}
	}

	for _, probe := range serverProbes {
		key := probe.RuleID + "|server"
		if seen[key] {
			continue
		}
		seen[key] = true
		entry := probe
		entry.Status = StatusUnproven
		hypotheses = append(hypotheses, entry)
	}

	sort.Slice(hypotheses, func(i, j int) bool {
		if hypotheses[i].Probe == hypotheses[j].Probe {
			return hypotheses[i].TargetTool < hypotheses[j].TargetTool
		}
		return hypotheses[i].Probe < hypotheses[j].Probe
	})
	return hypotheses
}

func Evaluate(hypotheses []Hypothesis, findings []auditor.Finding) []Hypothesis {
	confirmed := make(map[string]bool)
	for _, finding := range findings {
		if finding.Confirmed {
			confirmed[finding.RuleID+"|"+finding.TargetTool] = true
			confirmed[finding.RuleID+"|"] = true
		}
	}
	evaluated := make([]Hypothesis, len(hypotheses))
	copy(evaluated, hypotheses)
	for i := range evaluated {
		if confirmed[evaluated[i].RuleID+"|"+evaluated[i].TargetTool] || confirmed[evaluated[i].RuleID+"|"] {
			evaluated[i].Status = StatusConfirmed
		}
	}
	return evaluated
}

func Report(hypotheses []Hypothesis) string {
	if len(hypotheses) == 0 {
		return "Campaign: no hypotheses to test.\n"
	}
	confirmed := 0
	for _, hypothesis := range hypotheses {
		if hypothesis.Status == StatusConfirmed {
			confirmed++
		}
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "Campaign summary: %d hypotheses, %d confirmed, %d unproven\n",
		len(hypotheses), confirmed, len(hypotheses)-confirmed)
	for _, hypothesis := range hypotheses {
		marker := "[?]"
		if hypothesis.Status == StatusConfirmed {
			marker = "[!]"
		}
		fmt.Fprintf(&builder, "  %s %-22s %-18s via %s\n",
			marker, hypothesis.RuleID, displayTarget(hypothesis.TargetTool), hypothesis.Probe)
	}
	return builder.String()
}

func displayTarget(target string) string {
	if target == "" {
		return "server"
	}
	return target
}
