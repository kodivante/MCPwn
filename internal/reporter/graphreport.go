package reporter

import (
	"encoding/json"
	"fmt"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/capability"
	"github.com/kodivante/MCPwn/v3/internal/graph"
	"github.com/kodivante/MCPwn/v3/internal/risk"
)

type GraphReport struct {
	RiskIndex risk.Index           `json:"riskIndex"`
	Graph     graph.Graph          `json:"graph"`
	Reach     []graph.ToolReach    `json:"reach"`
	Chains    []graph.ChainSummary `json:"chains"`
}

func GenerateGraphReport(findings []auditor.Finding, profiles []capability.ToolCapability, entityGraph graph.Graph) ([]byte, error) {
	report := GraphReport{
		RiskIndex: risk.ServerIndex(findings),
		Graph:     entityGraph,
		Reach:     entityGraph.ReachReport(profiles),
		Chains:    entityGraph.ChainSummaries(profiles, findings),
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("graph report generation failed: %w", err)
	}
	return data, nil
}
