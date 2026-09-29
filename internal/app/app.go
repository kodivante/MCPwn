package app

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/attackchain"
	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/client"
	"github.com/kodivante/MCPwn/v3/internal/promptinject"
	"github.com/kodivante/MCPwn/v3/internal/schema"
)

type Config struct {
	TransportType string
	Command       string
	Args          []string
	URL           string
	AuthHeader    string
	OutputFormat  string
	OutputFile    string
	OutDirectory  string
	RecordPath    string
	TargetsFile   string
	Timeout       time.Duration
	Fuzz          bool
	FuzzTimeout   time.Duration
	PromptInject  bool
	GenPoC        bool
	PoCLang       string
	PoCDirectory  string
	Payloads      string
	Watch         bool
	WatchInterval time.Duration
	DiffFile      string
	Deep          bool
	Quick         bool
	Traversal     bool
	SSRF          bool
	Pollute       bool
	Desync        bool
	ProtoFuzz     bool
	RaceProbe     bool
	Exhaust       bool
	RugPull       bool
	TokenLeak     bool
	Sampling      bool
	SideChannel   bool
	ResTraversal  bool
	PromptAudit   bool
	HttpThreat    bool
	Elicitation   bool
	Roots         bool
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
	findings, err := auditOnce(ctx, cfg, connectFactory)
	if err != nil {
		return 1, err
	}
	return finalizeFindings(findings, cfg)
}

func auditOnce(ctx context.Context, cfg Config, connectFactory transportFactory) (findings []auditor.Finding, err error) {
	transport, err := connectFactory(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := transport.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	wrapped, wrapErr := withRecorder(transport, cfg)
	if wrapErr != nil {
		return nil, wrapErr
	}
	if wrapped != nil {
		transport = wrapped
	}
	session := client.NewSession(transport)
	if cfg.FuzzTimeout > 0 {
		session.SetRequestTimeout(cfg.FuzzTimeout)
	}
	if err = session.Initialize(); err != nil {
		return nil, err
	}
	var tools []schema.Tool
	if tools, err = session.ListTools(); err != nil {
		return nil, err
	}
	findings = audit(tools, cfg)
	return collectFindings(ctx, connectFactory, session, tools, findings, cfg)
}

func collectFindings(ctx context.Context, connectFactory transportFactory, session *client.Session, tools []schema.Tool, findings []auditor.Finding, cfg Config) ([]auditor.Finding, error) {
	if cfg.Fuzz {
		fuzzEngine, fuzzErr := newFuzzEngine(session, cfg)
		if fuzzErr != nil {
			return nil, fuzzErr
		}
		findings = fuzzEngine.ConfirmFindings(findings)
	}
	if cfg.PromptInject {
		promptEngine := promptinject.NewEngine(session, promptinject.Options{Timeout: cfg.FuzzTimeout})
		findings = append(findings, promptEngine.ProbeTools(tools)...)
	}
	findings = runDeepProbes(ctx, connectFactory, session, tools, findings, cfg)
	applyConfidence(findings)
	return attackchain.NewDetector().Analyze(findings), nil
}

func finalizeFindings(findings []auditor.Finding, cfg Config) (int, error) {
	if err := render(findings, cfg); err != nil {
		return 1, err
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
