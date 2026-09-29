package app

import (
	"context"
	"time"

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
	OutputFormat  string
	OutputFile    string
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
}

type transportFactory func(ctx context.Context, cfg Config) (client.Transport, error)

func Run(ctx context.Context, cfg Config) (int, error) {
	return runWith(ctx, cfg, connect)
}

func runWith(ctx context.Context, cfg Config, connectFactory transportFactory) (code int, err error) {
	cfg = resolveDeep(cfg)
	if cfg.Watch {
		return watchLoop(ctx, cfg, connectFactory)
	}
	transport, err := connectFactory(ctx, cfg)
	if err != nil {
		return 1, err
	}
	defer func() {
		if closeErr := transport.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	session := client.NewSession(transport)
	if err = session.Initialize(); err != nil {
		return 1, err
	}
	var tools []schema.Tool
	if tools, err = session.ListTools(); err != nil {
		return 1, err
	}

	findings := audit(tools, cfg)
	return processFindings(ctx, connectFactory, session, tools, findings, cfg)
}

func processFindings(ctx context.Context, connectFactory transportFactory, session *client.Session, tools []schema.Tool, findings []auditor.Finding, cfg Config) (int, error) {
	if cfg.Fuzz {
		fuzzEngine, fuzzErr := newFuzzEngine(session, cfg)
		if fuzzErr != nil {
			return 1, fuzzErr
		}
		findings = fuzzEngine.ConfirmFindings(findings)
	}
	if cfg.PromptInject {
		promptEngine := promptinject.NewEngine(session)
		findings = append(findings, promptEngine.ProbeTools(tools)...)
	}
	findings = runDeepProbes(ctx, connectFactory, session, tools, findings, cfg)
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
