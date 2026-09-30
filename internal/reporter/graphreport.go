package reporter

import (
	"encoding/json"
	"fmt"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/campaign"
	"github.com/kodivante/MCPwn/v3/internal/capability"
	"github.com/kodivante/MCPwn/v3/internal/graph"
	"github.com/kodivante/MCPwn/v3/internal/risk"
)

type GraphReport struct {
	RiskIndex risk.Index            `json:"riskIndex"`
	Graph     graph.Graph           `json:"graph"`
	Reach     []graph.ToolReach     `json:"reach"`
	Chains    []graph.ChainSummary  `json:"chains"`
	Campaign  []campaign.Hypothesis `json:"campaign,omitempty"`
}

func GenerateGraphReport(findings []auditor.Finding, profiles []capability.ToolCapability, entityGraph graph.Graph, hypotheses []campaign.Hypothesis) ([]byte, error) {
	report := GraphReport{
		RiskIndex: risk.ServerIndex(findings),
		Graph:     entityGraph,
		Reach:     entityGraph.ReachReport(profiles),
		Chains:    entityGraph.ChainSummaries(profiles, findings),
		Campaign:  hypotheses,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("graph report generation failed: %w", err)
	}
	return data, nil
}
