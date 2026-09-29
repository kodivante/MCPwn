package graph

import (
	"sort"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/capability"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

type NodeKind string

const (
	KindTool       NodeKind = "tool"
	KindCapability NodeKind = "capability"
)

const (
	EdgeReaches = "reaches"
	EdgeExposes = "exposes"
)

type Node struct {
	ID        string   `json:"id"`
	Kind      NodeKind `json:"kind"`
	Label     string   `json:"label"`
	Confirmed bool     `json:"confirmed,omitempty"`
}

type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type ToolReach struct {
	Tool  string   `json:"tool"`
	Reach []string `json:"reach"`
}

var confirmingRules = map[string]string{
	"CmdInjection01":      capability.Exec,
	"Ssrf01":              capability.Network,
	"PathTraversal01":     capability.Filesystem,
	"ResourceTraversal01": capability.Filesystem,
	"TokenLeak01":         capability.Credentials,
	"CredentialsLeak01":   capability.Credentials,
	"SqlInjection01":      capability.Database,
	"StateMutation01":     capability.State,
	"ContextSharing01":    capability.Credentials,
}

func toolNodeID(name string) string {
	return "tool:" + name
}

func capabilityNodeID(name string) string {
	return "capability:" + name
}

func BuildGraph(tools []schema.Tool, profiles []capability.ToolCapability, findings []auditor.Finding) Graph {
	entityGraph := Graph{Nodes: []Node{}, Edges: []Edge{}}
	confirmedCaps := confirmedCapabilities(findings)
	seenCapabilities := make(map[string]bool)

	for _, profile := range profiles {
		entityGraph.Nodes = append(entityGraph.Nodes, Node{
			ID:    toolNodeID(profile.Tool),
			Kind:  KindTool,
			Label: profile.Tool,
		})
		for _, capabilityName := range profile.Capabilities {
			if !seenCapabilities[capabilityName] {
				seenCapabilities[capabilityName] = true
				entityGraph.Nodes = append(entityGraph.Nodes, Node{
					ID:        capabilityNodeID(capabilityName),
					Kind:      KindCapability,
					Label:     capabilityName,
					Confirmed: confirmedCaps[capabilityName],
				})
			}
			entityGraph.Edges = append(entityGraph.Edges, Edge{
				From: toolNodeID(profile.Tool),
				To:   capabilityNodeID(capabilityName),
				Kind: EdgeReaches,
			})
		}
	}
	return entityGraph
}

func confirmedCapabilities(findings []auditor.Finding) map[string]bool {
	confirmed := make(map[string]bool)
	for _, finding := range findings {
		capabilityName, ok := confirmingRules[finding.RuleID]
		if !ok || !finding.Confirmed {
			continue
		}
		confirmed[capabilityName] = true
	}
	return confirmed
}

func (g Graph) ReachFrom(nodeID string) []string {
	adjacency := make(map[string][]string)
	for _, edge := range g.Edges {
		adjacency[edge.From] = append(adjacency[edge.From], edge.To)
	}
	visited := make(map[string]bool)
	queue := []string{nodeID}
	var reached []string
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, next := range adjacency[current] {
			if visited[next] {
				continue
			}
			visited[next] = true
			reached = append(reached, next)
			queue = append(queue, next)
		}
	}
	sort.Strings(reached)
	return reached
}

func (g Graph) ReachReport(profiles []capability.ToolCapability) []ToolReach {
	report := make([]ToolReach, 0, len(profiles))
	for _, profile := range profiles {
		capabilities := make([]string, len(profile.Capabilities))
		copy(capabilities, profile.Capabilities)
		report = append(report, ToolReach{Tool: profile.Tool, Reach: capabilities})
	}
	sort.Slice(report, func(i, j int) bool { return report[i].Tool < report[j].Tool })
	return report
}
