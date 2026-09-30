package app

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/advisor"
	"github.com/kodivante/MCPwn/v3/internal/attackchain"
	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/campaign"
	"github.com/kodivante/MCPwn/v3/internal/capability"
	"github.com/kodivante/MCPwn/v3/internal/client"
	"github.com/kodivante/MCPwn/v3/internal/graph"
	"github.com/kodivante/MCPwn/v3/internal/policy"
	"github.com/kodivante/MCPwn/v3/internal/promptinject"
	"github.com/kodivante/MCPwn/v3/internal/schema"
	"github.com/kodivante/MCPwn/v3/internal/snapshot"
	"github.com/kodivante/MCPwn/v3/internal/sourcescan"
	"github.com/kodivante/MCPwn/v3/internal/supplychain"
)

type Config struct {
	TransportType   string
	Command         string
	Args            []string
	URL             string
	AuthHeader      string
	OutputFormat    string
	OutputFile      string
	OutDirectory    string
	RecordPath      string
	TargetsFile     string
	SnapshotSave    string
	SnapshotCompare string
	SupplyChainPath string
	SourcePath      string
	AuthAudit       bool
	Discover        bool
	Autopilot       bool
	PolicyFile      string
	AdvisorEndpoint string
	Mutate          bool
	Sequence        bool
	Timeout         time.Duration
	Fuzz            bool
	FuzzTimeout     time.Duration
	PromptInject    bool
	GenPoC          bool
	PoCLang         string
	PoCDirectory    string
	Payloads        string
	Watch           bool
	WatchInterval   time.Duration
	DiffFile        string
	Deep            bool
	Quick           bool
	Traversal       bool
	SSRF            bool
	Pollute         bool
	Desync          bool
	ProtoFuzz       bool
	RaceProbe       bool
	Exhaust         bool
	RugPull         bool
	TokenLeak       bool
	Sampling        bool
	SideChannel     bool
	ResTraversal    bool
	PromptAudit     bool
	HttpThreat      bool
	Elicitation     bool
	Roots           bool
}

type auditArtifacts struct {
	profiles    []capability.ToolCapability
	entityGraph graph.Graph
	campaign    []campaign.Hypothesis
}

type transportFactory func(ctx context.Context, cfg Config) (client.Transport, error)

func Run(ctx context.Context, cfg Config) (int, error) {
	return runWith(ctx, cfg, connect)
}

func runWith(ctx context.Context, cfg Config, connectFactory transportFactory) (int, error) {
	cfg = resolveDeep(cfg)
	if cfg.Watch {
		return watchLoop(ctx, cfg, connectFactory)
	}
	findings, artifacts, err := auditOnce(ctx, cfg, connectFactory)
	if err != nil {
		return 1, err
	}
	return finalizeFindings(findings, artifacts, cfg)
}

func auditOnce(ctx context.Context, cfg Config, connectFactory transportFactory) (findings []auditor.Finding, artifacts auditArtifacts, err error) {
	transport, err := connectFactory(ctx, cfg)
	if err != nil {
		return nil, artifacts, err
	}
	defer func() {
		if closeErr := transport.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	wrapped, wrapErr := withRecorder(transport, cfg)
	if wrapErr != nil {
		return nil, artifacts, wrapErr
	}
	if wrapped != nil {
		transport = wrapped
	}
	session := client.NewSession(transport)
	if cfg.FuzzTimeout > 0 {
		session.SetRequestTimeout(cfg.FuzzTimeout)
	}
	if err = session.Initialize(); err != nil {
		return nil, artifacts, err
	}
	var tools []schema.Tool
	if tools, err = session.ListTools(); err != nil {
		return nil, artifacts, err
	}
	findings = audit(tools, cfg)
	return collectFindings(ctx, connectFactory, session, tools, findings, cfg)
}

func collectFindings(ctx context.Context, connectFactory transportFactory, session *client.Session, tools []schema.Tool, findings []auditor.Finding, cfg Config) ([]auditor.Finding, auditArtifacts, error) {
	artifacts := auditArtifacts{}
	artifacts.profiles = capability.Profile(tools)
	var hypotheses []campaign.Hypothesis
	if cfg.Autopilot {
		hypotheses = campaign.BuildHypotheses(findings, artifacts.profiles)
	}
	if cfg.Fuzz {
		fuzzEngine, fuzzErr := newFuzzEngine(session, cfg)
		if fuzzErr != nil {
			return nil, artifacts, fuzzErr
		}
		findings = fuzzEngine.ConfirmFindings(findings)
	}
	if cfg.PromptInject {
		promptEngine := promptinject.NewEngine(session, promptinject.Options{Timeout: cfg.FuzzTimeout})
		findings = append(findings, promptEngine.ProbeTools(tools)...)
	}
	findings = runDeepProbes(ctx, connectFactory, session, tools, findings, cfg, artifacts.profiles)
	localFindings, localErr := localScanFindings(cfg)
	if localErr != nil {
		return nil, artifacts, localErr
	}
	findings = append(findings, localFindings...)
	advisorFindings, advisorErr := runAdvisor(cfg, findings, artifacts.profiles)
	if advisorErr != nil {
		return nil, artifacts, advisorErr
	}
	findings = append(findings, advisorFindings...)
	if err := runSnapshotWorkflow(session, tools, &findings, &artifacts, cfg); err != nil {
		return nil, artifacts, err
	}
	artifacts.entityGraph = graph.BuildGraph(tools, artifacts.profiles, findings)
	findings = append(findings, artifacts.entityGraph.DetectChains(artifacts.profiles, findings)...)
	findings = attackchain.NewDetector().Analyze(findings)
	applyConfidence(findings)
	if cfg.Autopilot {
		artifacts.campaign = campaign.Evaluate(hypotheses, findings)
	}
	return findings, artifacts, nil
}

func runAdvisor(cfg Config, findings []auditor.Finding, profiles []capability.ToolCapability) ([]auditor.Finding, error) {
	if cfg.AdvisorEndpoint == "" {
		return nil, nil
	}
	engine := advisor.NewEngine(advisor.Options{Endpoint: cfg.AdvisorEndpoint, Timeout: cfg.FuzzTimeout})
	hints, err := engine.Consult(findings, profiles)
	if err != nil {
		return nil, fmt.Errorf("advisor consult failed: %w", err)
	}
	return hints, nil
}

func localScanFindings(cfg Config) ([]auditor.Finding, error) {
	var findings []auditor.Finding
	if cfg.SourcePath != "" {
		sourceFindings, err := sourcescan.ScanTree(cfg.SourcePath)
		if err != nil {
			return nil, fmt.Errorf("source scan failed: %w", err)
		}
		findings = append(findings, sourceFindings...)
	}
	if cfg.SupplyChainPath != "" {
		engine := supplychain.NewEngine(supplychain.Options{})
		supplyFindings, err := engine.Audit(cfg.SupplyChainPath)
		if err != nil {
			return nil, fmt.Errorf("supply chain audit failed: %w", err)
		}
		findings = append(findings, supplyFindings...)
	}
	return findings, nil
}

func runSnapshotWorkflow(session *client.Session, tools []schema.Tool, findings *[]auditor.Finding, artifacts *auditArtifacts, cfg Config) error {
	if cfg.SnapshotSave == "" && cfg.SnapshotCompare == "" {
		return nil
	}
	if cfg.SnapshotSave != "" {
		shapes := snapshot.CollectShapes(session, tools)
		if err := snapshot.Save(cfg.SnapshotSave, tools, artifacts.profiles, shapes); err != nil {
			return fmt.Errorf("snapshot save failed: %w", err)
		}
	}
	if cfg.SnapshotCompare != "" {
		drift, err := snapshot.Compare(cfg.SnapshotCompare, session, tools, artifacts.profiles)
		if err != nil {
			return fmt.Errorf("snapshot compare failed: %w", err)
		}
		*findings = append(*findings, drift...)
	}
	return nil
}

func finalizeFindings(findings []auditor.Finding, artifacts auditArtifacts, cfg Config) (int, error) {
	if err := render(findings, artifacts, cfg); err != nil {
		return 1, err
	}
	if len(artifacts.campaign) > 0 && cfg.OutputFormat == "terminal" {
		fmt.Print(campaign.Report(artifacts.campaign))
	}
	if cfg.PolicyFile != "" {
		target, err := policy.Load(cfg.PolicyFile)
		if err != nil {
			return 1, err
		}
		violations, fail := policy.Evaluate(target, findings)
		printPolicyReport(policy.Report(violations), cfg.OutputFormat)
		if fail {
			return 1, nil
		}
	}
	if cfg.DiffFile != "" {
		if err := runDiff(findings, cfg.DiffFile); err != nil {
			return 1, err
		}
	}
	if cfg.GenPoC {
		if err := generatePoCs(findings, cfg); err != nil {
			return 1, err
		}
	}
	return exitCode(findings), nil
}

func printPolicyReport(report string, outputFormat string) {
	if outputFormat == "terminal" {
		fmt.Print(report)
		return
	}
	fmt.Fprint(os.Stderr, report)
}

func withRecorder(transport client.Transport, cfg Config) (client.Transport, error) {
	if cfg.RecordPath == "" {
		return transport, nil
	}
	file, err := os.Create(cfg.RecordPath)
	if err != nil {
		return nil, fmt.Errorf("record file creation failed: %w", err)
	}
	return client.NewRecordingTransport(transport, file), nil
}
