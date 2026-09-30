package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/app"
	"github.com/kodivante/MCPwn/v3/internal/version"
)

func main() {
	cfg, showVersion := parseConfig()

	if showVersion {
		fmt.Printf(`MCPwn v%s
Security Auditor and Fuzzing Linter for MCP
Designed and developed by kodivante
`, version.Version)
		return
	}

	var ctx context.Context
	var cancel context.CancelFunc
	if cfg.TargetsFile != "" {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithTimeout(context.Background(), cfg.Timeout)
		if cfg.Watch {
			cancel()
			ctx, cancel = signal.NotifyContext(context.Background(), os.Interrupt)
		}
	}
	defer cancel()

	var exitCode int
	var err error
	switch {
	case cfg.Discover:
		exitCode, err = app.RunDiscover(cfg)
	case cfg.TargetsFile != "":
		exitCode, err = app.RunBatch(ctx, cfg)
	case cfg.SourcePath != "" && cfg.Command == "" && cfg.URL == "":
		exitCode, err = app.RunSourceScan(ctx, cfg)
	default:
		exitCode, err = app.Run(ctx, cfg)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcpwn: %v\n", err)
		os.Exit(1)
	}
	os.Exit(exitCode)
}

type cliFlags struct {
	transportType   *string
	command         *string
	args            *string
	url             *string
	authHeader      *string
	output          *string
	file            *string
	outdir          *string
	record          *string
	targets         *string
	snapshotSave    *string
	snapshotCompare *string
	sourcePath      *string
	supplyChain     *string
	authAudit       *bool
	discover        *bool
	autopilot       *bool
	policyFile      *string
	advisorEndpoint *string
	mutate          *bool
	sequence        *bool
	timeout         *time.Duration
	fuzz            *bool
	fuzzTimeout     *time.Duration
	promptInject    *bool
	genPoC          *bool
	pocLang         *string
	payloadsPath    *string
	watch           *bool
	watchInterval   *time.Duration
	diffFile        *string
	showVersion     *bool
	deep            *bool
	quick           *bool
	traverse        *bool
	ssrf            *bool
	pollute         *bool
	desync          *bool
	protoFuzz       *bool
	raceProbe       *bool
	exhaust         *bool
	rugPull         *bool
	tokenLeak       *bool
	sampling        *bool
	sideChannel     *bool
	resTraversal    *bool
	promptAudit     *bool
	httpProbe       *bool
	elicitation     *bool
	roots           *bool
}

func parseConfig() (app.Config, bool) {
	registerUsage()
	flags := declareFlags()
	return flags.buildConfig(), *flags.showVersion
}

func registerUsage() {
	flag.Usage = func() {
		fmt.Print(`MCPwn - Security Auditor and Fuzzing Linter for MCP
Designed and developed by kodivante

Usage:
  mcpwn [flags]

Flags:
  -transport string          Transport type: 'stdio', 'sse' or 'http' (default "stdio")
  -command string            Command to run for stdio transport (e.g. node)
  -args string               Arguments for the command, comma separated (e.g. server.js)
  -url string                URL for sse/http transports (e.g. http://localhost:8080/mcp)
  -auth-header string        Authorization header value for http transport (e.g. "Bearer token")
  -output string             Output format: 'terminal', 'json', 'sarif', 'html', 'badge', 'graph' (default "terminal")
  -file string               Path to save the output file (optional)
  -outdir string             Directory for per-target reports in batch mode (optional)
  -record string            Path to save a JSONL transcript of every JSON-RPC message (optional)
  -targets string           Batch mode: JSON file with an array of targets to audit
  -snapshot-save string     Save an approved-tool fingerprint snapshot to the given path
  -snapshot-compare string  Compare the current server against a snapshot and report drift
  -timeout duration          Total audit timeout, per target in batch mode (default 30s)
  -fuzz                      Run dynamic fuzzing to confirm command injection findings
  -fuzz-timeout duration     Per-probe fuzz timeout (default 10s)
  -prompt-inject             Probe tools with benign prompt injection payloads
  -gen-poc                   Generate didactic PoC scripts for confirmed findings into ./pocs
  -poc-lang string           PoC language: 'python' or 'bash' (default "python")
  -payloads string          Load custom fuzz payloads from a .mcpwn file or directory (plus auto-loads ./mcpwn.d)
  -watch                     Run continuously and re-audit on interval
  -interval duration         Watch interval (default 30s)
  -diff string               Baseline report file to compare against
  -deep                      Enable every dynamic engine in one flag
  -quick                     Stop deep probing after the first confirmed finding
  -traverse                  Confirm path traversal findings with a marker file
  -ssrf                      Confirm SSRF findings with a local canary listener
  -pollute                   Confirm mass assignment findings with undeclared properties
  -desync                    Probe MCP lifecycle state handling
  -protofuzz                 Send malformed JSON-RPC messages and detect crashes
  -race-probe                Send identical concurrent tool calls
  -exhaust                   Measure latency degradation under a bounded request burst
  -rugpull                   Detect tool description changes across sessions
  -tokenleak                 Scan tool responses and errors for leaked credentials
  -sampling                  Detect if server accepts sampling/createMessage
  -side-channel              Detect blind injection via timing, size and error side-channels
  -restraverse               Probe resources/read with traversal payloads
  -prompt-audit              Audit prompt templates for hidden instructions and exfiltration
  -http-probe                Probe http transport security: auth bypass, session and origin validation
  -elicitation               Detect if server accepts elicitation/create requests
  -roots                     Detect if server accepts roots/list requests
  -version                   Print version and exit
`)
	}
}

func declareFlags() cliFlags {
	flags := cliFlags{
		transportType:   flag.String("transport", "stdio", "Transport type (stdio, sse, http)"),
		command:         flag.String("command", "", "Command to run for stdio transport"),
		args:            flag.String("args", "", "Arguments for the command (comma separated)"),
		url:             flag.String("url", "", "URL for sse or http transport"),
		authHeader:      flag.String("auth-header", "", "Authorization header value for http transport"),
		output:          flag.String("output", "terminal", "Output format (terminal, json, sarif, html, badge, graph)"),
		file:            flag.String("file", "", "Output file path"),
		outdir:          flag.String("outdir", "", "Directory for per-target reports in batch mode"),
		record:          flag.String("record", "", "JSONL transcript path for every JSON-RPC message"),
		targets:         flag.String("targets", "", "Batch mode targets JSON file"),
		snapshotSave:    flag.String("snapshot-save", "", "Save an approved-tool fingerprint snapshot"),
		snapshotCompare: flag.String("snapshot-compare", "", "Compare the server against a snapshot"),
		sourcePath:      flag.String("source", "", "Source tree to scan for dangerous sinks and secrets"),
		supplyChain:     flag.String("supply-chain", "", "Project path with manifests to audit dependencies"),
		authAudit:       flag.Bool("auth-audit", false, "Probe OAuth metadata, PKCE and token validation"),
		discover:        flag.Bool("discover", false, "Discover MCP servers configured on this machine"),
		autopilot:       flag.Bool("autopilot", false, "Run the full hypothesis-driven campaign with a summary"),
		policyFile:      flag.String("policy", "", "Policy file with security gates (failOn, maxFindings, ignoreRules)"),
		advisorEndpoint: flag.String("advisor-endpoint", "", "Optional LLM advisor endpoint receiving anonymized context for hypotheses"),
		mutate:          flag.Bool("mutate", false, "Detect input processing via mutation response differentials"),
		sequence:        flag.Bool("sequence", false, "Probe idempotency and cross-tool state drift"),
		timeout:         flag.Duration("timeout", 30*time.Second, "Total audit timeout"),
		fuzz:            flag.Bool("fuzz", false, "Run dynamic fuzzing to confirm findings"),
		fuzzTimeout:     flag.Duration("fuzz-timeout", 10*time.Second, "Per-probe fuzz timeout"),
		promptInject:    flag.Bool("prompt-inject", false, "Probe tools with benign prompt injection payloads"),
		genPoC:          flag.Bool("gen-poc", false, "Generate didactic PoC scripts for confirmed findings"),
		pocLang:         flag.String("poc-lang", "python", "PoC language (python, bash)"),
		payloadsPath:    flag.String("payloads", "", "Custom fuzz payloads (.mcpwn file or directory)"),
		watch:           flag.Bool("watch", false, "Run continuously and re-audit on interval"),
		watchInterval:   flag.Duration("interval", 30*time.Second, "Watch mode interval"),
		diffFile:        flag.String("diff", "", "Baseline report file to compare against"),
		showVersion:     flag.Bool("version", false, "Print version and exit"),
		deep:            flag.Bool("deep", false, "Enable every dynamic engine in one flag"),
		quick:           flag.Bool("quick", false, "Stop deep probing after the first confirmed finding"),
		traverse:        flag.Bool("traverse", false, "Confirm path traversal findings with a marker file"),
		ssrf:            flag.Bool("ssrf", false, "Confirm SSRF findings with a local canary listener"),
		pollute:         flag.Bool("pollute", false, "Confirm mass assignment findings with undeclared properties"),
		desync:          flag.Bool("desync", false, "Probe MCP lifecycle state handling"),
		protoFuzz:       flag.Bool("protofuzz", false, "Send malformed JSON-RPC messages and detect crashes"),
		raceProbe:       flag.Bool("race-probe", false, "Send identical concurrent tool calls"),
		exhaust:         flag.Bool("exhaust", false, "Measure latency degradation under a bounded request burst"),
		rugPull:         flag.Bool("rugpull", false, "Detect tool description changes across sessions"),
		tokenLeak:       flag.Bool("tokenleak", false, "Scan tool responses and errors for leaked credentials"),
		sampling:        flag.Bool("sampling", false, "Detect if server accepts sampling/createMessage"),
		sideChannel:     flag.Bool("side-channel", false, "Detect blind injection via side-channels"),
		resTraversal:    flag.Bool("restraverse", false, "Probe resources/read with traversal payloads"),
		promptAudit:     flag.Bool("prompt-audit", false, "Audit prompt templates for hidden instructions"),
		httpProbe:       flag.Bool("http-probe", false, "Probe http transport security"),
		elicitation:     flag.Bool("elicitation", false, "Detect if server accepts elicitation/create"),
		roots:           flag.Bool("roots", false, "Detect if server accepts roots/list"),
	}
	flag.Parse()
	return flags
}

func (f cliFlags) buildConfig() app.Config {
	return app.Config{
		TransportType:   *f.transportType,
		Command:         *f.command,
		Args:            parseArgs(*f.args),
		URL:             *f.url,
		AuthHeader:      *f.authHeader,
		OutputFormat:    *f.output,
		OutputFile:      *f.file,
		OutDirectory:    *f.outdir,
		RecordPath:      *f.record,
		TargetsFile:     *f.targets,
		SnapshotSave:    *f.snapshotSave,
		SnapshotCompare: *f.snapshotCompare,
		SourcePath:      *f.sourcePath,
		SupplyChainPath: *f.supplyChain,
		AuthAudit:       *f.authAudit,
		Discover:        *f.discover,
		Autopilot:       *f.autopilot,
		PolicyFile:      *f.policyFile,
		AdvisorEndpoint: *f.advisorEndpoint,
		Mutate:          *f.mutate,
		Sequence:        *f.sequence,
		Timeout:         *f.timeout,
		Fuzz:            *f.fuzz,
		FuzzTimeout:     *f.fuzzTimeout,
		PromptInject:    *f.promptInject,
		GenPoC:          *f.genPoC,
		PoCLang:         *f.pocLang,
		PoCDirectory:    "pocs",
		Payloads:        *f.payloadsPath,
		Watch:           *f.watch,
		WatchInterval:   *f.watchInterval,
		DiffFile:        *f.diffFile,
		Deep:            *f.deep,
		Quick:           *f.quick,
		Traversal:       *f.traverse,
		SSRF:            *f.ssrf,
		Pollute:         *f.pollute,
		Desync:          *f.desync,
		ProtoFuzz:       *f.protoFuzz,
		RaceProbe:       *f.raceProbe,
		Exhaust:         *f.exhaust,
		RugPull:         *f.rugPull,
		TokenLeak:       *f.tokenLeak,
		Sampling:        *f.sampling,
		SideChannel:     *f.sideChannel,
		ResTraversal:    *f.resTraversal,
		PromptAudit:     *f.promptAudit,
		HttpThreat:      *f.httpProbe,
		Elicitation:     *f.elicitation,
		Roots:           *f.roots,
	}
}

func parseArgs(argsStr string) []string {
	if argsStr == "" {
		return nil
	}
	return strings.Split(argsStr, ",")
}
