package graph

import (
	"strings"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/capability"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

func buildFixture() ([]schema.Tool, []capability.ToolCapability, []auditor.Finding) {
	tools := []schema.Tool{
		{Name: "systemExec", Description: "Execute an OS command", InputSchema: schema.JSONSchema{
			Type: "object", Properties: map[string]schema.JSONSchema{"cmd": {Type: "string"}},
		}},
		{Name: "fetchUrl", InputSchema: schema.JSONSchema{
			Type: "object", Properties: map[string]schema.JSONSchema{"url": {Type: "string"}},
		}},
		{Name: "loginUser", InputSchema: schema.JSONSchema{
			Type: "object", Properties: map[string]schema.JSONSchema{"password": {Type: "string"}},
		}},
	}
	profiles := capability.Profile(tools)
	findings := []auditor.Finding{
		{RuleID: "TokenLeak01", TargetTool: "loginUser", Severity: auditor.SeverityCritical, Confirmed: true},
		{RuleID: "CmdInjection01", TargetTool: "systemExec", Severity: auditor.SeverityCritical},
		{RuleID: "Ssrf01", TargetTool: "fetchUrl", Severity: auditor.SeverityMedium},
	}
	return tools, profiles, findings
}

func TestBuildGraphNodes(t *testing.T) {
	tools, profiles, findings := buildFixture()
	entityGraph := BuildGraph(tools, profiles, findings)
	toolNodes := 0
	capabilityNodes := 0
	for _, node := range entityGraph.Nodes {
		switch node.Kind {
		case KindTool:
			toolNodes++
		case KindCapability:
			capabilityNodes++
		}
	}
	if toolNodes != 3 {
		t.Errorf("expected 3 tool nodes, got %d", toolNodes)
	}
	if capabilityNodes == 0 {
		t.Error("expected capability nodes")
	}
	if len(entityGraph.Edges) == 0 {
		t.Error("expected edges")
	}
}

func TestBuildGraphMarksConfirmedCapabilities(t *testing.T) {
	tools, profiles, findings := buildFixture()
	entityGraph := BuildGraph(tools, profiles, findings)
	for _, node := range entityGraph.Nodes {
		if node.ID == capabilityNodeID(capability.Credentials) {
			if !node.Confirmed {
				t.Error("expected credentials capability confirmed by TokenLeak01")
			}
		}
		if node.ID == capabilityNodeID(capability.Exec) {
			if node.Confirmed {
				t.Error("exec capability must stay unconfirmed with unconfirmed CmdInjection01")
			}
		}
	}
}

func TestReachFromTool(t *testing.T) {
	tools, profiles, findings := buildFixture()
	entityGraph := BuildGraph(tools, profiles, findings)
	reach := entityGraph.ReachFrom(toolNodeID("systemExec"))
	if len(reach) == 0 {
		t.Fatal("expected reach from systemExec")
	}
	found := false
	for _, node := range reach {
		if node == capabilityNodeID(capability.Exec) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exec capability reachable, got %v", reach)
	}
}

func TestDetectChainsExfiltrationPipeline(t *testing.T) {
	tools, profiles, findings := buildFixture()
	entityGraph := BuildGraph(tools, profiles, findings)
	chains := entityGraph.DetectChains(profiles, findings)
	found := false
	for _, chain := range chains {
		if chain.RuleID != "AttackChain02" {
			t.Errorf("unexpected rule id %s", chain.RuleID)
		}
		if chain.Severity == auditor.SeverityCritical && strings.Contains(chain.Description, "exfiltration pipeline") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected critical exfiltration chain, got %+v", chains)
	}
}

func TestDetectChainsRequiresCapabilities(t *testing.T) {
	tools := []schema.Tool{
		{Name: "loginUser", InputSchema: schema.JSONSchema{
			Type: "object", Properties: map[string]schema.JSONSchema{"password": {Type: "string"}},
		}},
	}
	profiles := capability.Profile(tools)
	findings := []auditor.Finding{
		{RuleID: "TokenLeak01", TargetTool: "loginUser", Confirmed: true},
	}
	entityGraph := BuildGraph(tools, profiles, findings)
	if chains := entityGraph.DetectChains(profiles, findings); len(chains) != 0 {
		t.Errorf("expected 0 chains without exec/network caps, got %+v", chains)
	}
}

func TestDetectChainsDowngradesWithoutFullConfirmation(t *testing.T) {
	tools, profiles, findings := buildFixture()
	findings[0].Confirmed = false
	entityGraph := BuildGraph(tools, profiles, findings)
	chains := entityGraph.DetectChains(profiles, findings)
	for _, chain := range chains {
		if strings.Contains(chain.Description, "exfiltration pipeline") {
			if chain.Severity == auditor.SeverityCritical {
				t.Error("expected downgraded severity with unconfirmed anchor")
			}
			if chain.Confirmed {
				t.Error("chain must not be confirmed with unconfirmed anchor")
			}
		}
	}
}

func TestChainSummaries(t *testing.T) {
	tools, profiles, findings := buildFixture()
	entityGraph := BuildGraph(tools, profiles, findings)
	summaries := entityGraph.ChainSummaries(profiles, findings)
	if len(summaries) == 0 {
		t.Fatal("expected chain summaries")
	}
	for _, summary := range summaries {
		if summary.Path == "" {
			t.Error("expected path evidence in summaries")
		}
	}
}
