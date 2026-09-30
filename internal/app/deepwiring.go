package app

import (
	"context"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/authaudit"
	"github.com/kodivante/MCPwn/v3/internal/capability"
	"github.com/kodivante/MCPwn/v3/internal/client"
	"github.com/kodivante/MCPwn/v3/internal/desync"
	"github.com/kodivante/MCPwn/v3/internal/exhaustion"
	"github.com/kodivante/MCPwn/v3/internal/httpthreat"
	"github.com/kodivante/MCPwn/v3/internal/mutator"
	"github.com/kodivante/MCPwn/v3/internal/pollution"
	"github.com/kodivante/MCPwn/v3/internal/promptaudit"
	"github.com/kodivante/MCPwn/v3/internal/protocolfuzz"
	"github.com/kodivante/MCPwn/v3/internal/raceprober"
	"github.com/kodivante/MCPwn/v3/internal/restraversal"
	"github.com/kodivante/MCPwn/v3/internal/rugpull"
	"github.com/kodivante/MCPwn/v3/internal/samplingabuse"
	"github.com/kodivante/MCPwn/v3/internal/schema"
	"github.com/kodivante/MCPwn/v3/internal/sequencefuzz"
	"github.com/kodivante/MCPwn/v3/internal/serverrequest"
	"github.com/kodivante/MCPwn/v3/internal/sidechannel"
	"github.com/kodivante/MCPwn/v3/internal/ssrfcanary"
	"github.com/kodivante/MCPwn/v3/internal/tokenleak"
	"github.com/kodivante/MCPwn/v3/internal/traversal"
)

func resolveDeep(cfg Config) Config {
	if cfg.Autopilot {
		cfg.Deep = true
	}
	if !cfg.Deep {
		return cfg
	}
	cfg.Fuzz = true
	cfg.PromptInject = true
	cfg.Traversal = true
	cfg.SSRF = true
	cfg.Pollute = true
	cfg.Desync = true
	cfg.ProtoFuzz = true
	cfg.RaceProbe = true
	cfg.Exhaust = true
	cfg.RugPull = true
	cfg.TokenLeak = true
	cfg.Sampling = true
	cfg.SideChannel = true
	cfg.ResTraversal = true
	cfg.PromptAudit = true
	cfg.HttpThreat = true
	cfg.Elicitation = true
	cfg.Roots = true
	cfg.AuthAudit = true
	cfg.Mutate = true
	cfg.Sequence = true
	return cfg
}

func runDeepProbes(ctx context.Context, connectFactory transportFactory, session *client.Session, tools []schema.Tool, findings []auditor.Finding, cfg Config, profiles []capability.ToolCapability) []auditor.Finding {
	source := func() (client.Transport, error) {
		return connectFactory(ctx, cfg)
	}

	findings = confirmToolProbes(session, tools, findings, cfg)
	if cfg.Quick && hasConfirmed(findings) {
		return findings
	}

	findings = append(findings, lifecycleProbes(source, cfg)...)
	if cfg.Quick && hasConfirmed(findings) {
		return findings
	}

	findings = append(findings, loadProbes(session, source, tools, profiles, cfg)...)
	return findings
}

func confirmToolProbes(session *client.Session, tools []schema.Tool, findings []auditor.Finding, cfg Config) []auditor.Finding {
	if cfg.Traversal {
		engine := traversal.NewEngine(session, traversal.Options{Timeout: cfg.FuzzTimeout})
		findings = engine.ConfirmFindings(findings)
	}
	if cfg.Quick && hasConfirmed(findings) {
		return findings
	}
	if cfg.SSRF {
		engine := ssrfcanary.NewEngine(session, ssrfcanary.Options{Timeout: cfg.FuzzTimeout})
		findings = engine.ConfirmFindings(findings)
	}
	if cfg.Quick && hasConfirmed(findings) {
		return findings
	}
	if cfg.Pollute {
		engine := pollution.NewEngine(session, tools, pollution.Options{Timeout: cfg.FuzzTimeout})
		findings = engine.ConfirmFindings(findings)
	}
	return findings
}

func lifecycleProbes(source func() (client.Transport, error), cfg Config) []auditor.Finding {
	var findings []auditor.Finding
	if cfg.Desync {
		engine := desync.NewEngine(source, desync.Options{})
		findings = append(findings, engine.Probe()...)
	}
	if cfg.ProtoFuzz {
		engine := protocolfuzz.NewEngine(source, protocolfuzz.Options{})
		findings = append(findings, engine.Probe()...)
	}
	if cfg.RugPull {
		engine := rugpull.NewEngine(source, rugpull.Options{})
		findings = append(findings, engine.Probe()...)
	}
	if cfg.Sampling {
		engine := samplingabuse.NewEngine(source, samplingabuse.Options{})
		findings = append(findings, engine.Probe()...)
	}
	if cfg.Elicitation {
		engine := serverrequest.NewEngine(source, serverrequest.Options{})
		findings = append(findings, engine.ProbeElicitation()...)
	}
	if cfg.Roots {
		engine := serverrequest.NewEngine(source, serverrequest.Options{})
		findings = append(findings, engine.ProbeRoots()...)
	}
	if cfg.HttpThreat && cfg.TransportType == "http" {
		engine := httpthreat.NewEngine(cfg.URL, httpthreat.Options{AuthHeader: cfg.AuthHeader, Timeout: cfg.FuzzTimeout})
		findings = append(findings, engine.Probe()...)
	}
	if cfg.AuthAudit && cfg.TransportType == "http" {
		engine := authaudit.NewEngine(cfg.URL, cfg.AuthHeader, authaudit.Options{Timeout: cfg.FuzzTimeout})
		findings = append(findings, engine.Probe()...)
	}
	return findings
}

func loadProbes(session *client.Session, source func() (client.Transport, error), tools []schema.Tool, profiles []capability.ToolCapability, cfg Config) []auditor.Finding {
	var findings []auditor.Finding
	if cfg.RaceProbe {
		engine := raceprober.NewEngine(source, tools, raceprober.Options{Timeout: cfg.FuzzTimeout})
		findings = append(findings, engine.Probe()...)
	}
	if cfg.Exhaust {
		engine := exhaustion.NewEngine(session, exhaustion.Options{})
		findings = append(findings, engine.Probe()...)
	}
	if cfg.TokenLeak {
		engine := tokenleak.NewEngine(session, tools, tokenleak.Options{Timeout: cfg.FuzzTimeout})
		findings = append(findings, engine.ProbeTools()...)
	}
	if cfg.SideChannel {
		engine := sidechannel.NewEngine(session, tools, sidechannel.Options{Timeout: cfg.FuzzTimeout})
		findings = append(findings, engine.Probe()...)
	}
	if cfg.ResTraversal {
		engine := restraversal.NewEngine(session, restraversal.Options{Timeout: cfg.FuzzTimeout})
		findings = append(findings, engine.Probe()...)
	}
	if cfg.PromptAudit {
		engine := promptaudit.NewEngine(session, promptaudit.Options{})
		findings = append(findings, engine.Probe()...)
	}
	if cfg.Mutate {
		engine := mutator.NewEngine(session, tools, mutator.Options{Timeout: cfg.FuzzTimeout})
		findings = append(findings, engine.Probe()...)
	}
	if cfg.Sequence {
		engine := sequencefuzz.NewEngine(session, tools, profiles, sequencefuzz.Options{Timeout: cfg.FuzzTimeout})
		findings = append(findings, engine.Probe()...)
	}
	return findings
}

func hasConfirmed(findings []auditor.Finding) bool {
	for _, finding := range findings {
		if finding.Confirmed {
			return true
		}
	}
	return false
}
