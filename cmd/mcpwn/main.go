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

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	if cfg.Watch {
		cancel()
		ctx, cancel = signal.NotifyContext(context.Background(), os.Interrupt)
	}
	defer cancel()

	exitCode, err := app.Run(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcpwn: %v\n", err)
		os.Exit(1)
	}
	os.Exit(exitCode)
}

type cliFlags struct {
	transportType *string
	command       *string
	args          *string
	url           *string
	output        *string
	file          *string
	timeout       *time.Duration
	fuzz          *bool
	fuzzTimeout   *time.Duration
	promptInject  *bool
	genPoC        *bool
	pocLang       *string
	payloadsPath  *string
	watch         *bool
	watchInterval *time.Duration
	diffFile      *string
	showVersion   *bool
	deep          *bool
	quick         *bool
	traverse      *bool
	ssrf          *bool
	pollute       *bool
	desync        *bool
	protoFuzz     *bool
	raceProbe     *bool
	exhaust       *bool
	rugPull       *bool
	tokenLeak     *bool
	sampling      *bool
	sideChannel   *bool
	resTraversal  *bool
	promptAudit   *bool
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
  -transport string          Transport type: 'stdio' or 'sse' (default "stdio")
  -command string            Command to run for stdio transport (e.g. node)
  -args string               Arguments for the command, comma separated (e.g. server.js)
  -url string                URL for sse transport (e.g. http://localhost:8080/sse)
  -output string             Output format: 'terminal', 'json', 'sarif', 'html', 'badge' (default "terminal")
  -file string               Path to save the output file (optional)
  -timeout duration          Total audit timeout (default 30s)
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
  -version                   Print version and exit
`)
	}
}

func declareFlags() cliFlags {
	flags := cliFlags{
		transportType: flag.String("transport", "stdio", "Transport type (stdio, sse)"),
		command:       flag.String("command", "", "Command to run for stdio transport"),
		args:          flag.String("args", "", "Arguments for the command (comma separated)"),
		url:           flag.String("url", "", "URL for sse transport"),
		output:        flag.String("output", "terminal", "Output format (terminal, json, sarif, html, badge)"),
		file:          flag.String("file", "", "Output file path"),
		timeout:       flag.Duration("timeout", 30*time.Second, "Total audit timeout"),
		fuzz:          flag.Bool("fuzz", false, "Run dynamic fuzzing to confirm findings"),
		fuzzTimeout:   flag.Duration("fuzz-timeout", 10*time.Second, "Per-probe fuzz timeout"),
		promptInject:  flag.Bool("prompt-inject", false, "Probe tools with benign prompt injection payloads"),
		genPoC:        flag.Bool("gen-poc", false, "Generate didactic PoC scripts for confirmed findings"),
		pocLang:       flag.String("poc-lang", "python", "PoC language (python, bash)"),
		payloadsPath:  flag.String("payloads", "", "Custom fuzz payloads (.mcpwn file or directory)"),
		watch:         flag.Bool("watch", false, "Run continuously and re-audit on interval"),
		watchInterval: flag.Duration("interval", 30*time.Second, "Watch interval"),
		diffFile:      flag.String("diff", "", "Baseline report file to compare against"),
		showVersion:   flag.Bool("version", false, "Print version and exit"),
		deep:          flag.Bool("deep", false, "Enable every dynamic engine in one flag"),
		quick:         flag.Bool("quick", false, "Stop deep probing after the first confirmed finding"),
		traverse:      flag.Bool("traverse", false, "Confirm path traversal findings with a marker file"),
		ssrf:          flag.Bool("ssrf", false, "Confirm SSRF findings with a local canary listener"),
		pollute:       flag.Bool("pollute", false, "Confirm mass assignment findings with undeclared properties"),
		desync:        flag.Bool("desync", false, "Probe MCP lifecycle state handling"),
		protoFuzz:     flag.Bool("protofuzz", false, "Send malformed JSON-RPC messages and detect crashes"),
		raceProbe:     flag.Bool("race-probe", false, "Send identical concurrent tool calls"),
		exhaust:       flag.Bool("exhaust", false, "Measure latency degradation under a bounded request burst"),
		rugPull:       flag.Bool("rugpull", false, "Detect tool description changes across sessions"),
		tokenLeak:     flag.Bool("tokenleak", false, "Scan tool responses and errors for leaked credentials"),
		sampling:      flag.Bool("sampling", false, "Detect if server accepts sampling/createMessage"),
		sideChannel:   flag.Bool("side-channel", false, "Detect blind injection via timing, size and error side-channels"),
		resTraversal:  flag.Bool("restraverse", false, "Probe resources/read with traversal payloads"),
		promptAudit:   flag.Bool("prompt-audit", false, "Audit prompt templates for hidden instructions and exfiltration"),
	}
	flag.Parse()
	return flags
}

func (f cliFlags) buildConfig() app.Config {
	return app.Config{
		TransportType: *f.transportType,
		Command:       *f.command,
		Args:          parseArgs(*f.args),
		URL:           *f.url,
		OutputFormat:  *f.output,
		OutputFile:    *f.file,
		Timeout:       *f.timeout,
		Fuzz:          *f.fuzz,
		FuzzTimeout:   *f.fuzzTimeout,
		PromptInject:  *f.promptInject,
		GenPoC:        *f.genPoC,
		PoCLang:       *f.pocLang,
		PoCDirectory:  "pocs",
		Payloads:      *f.payloadsPath,
		Watch:         *f.watch,
		WatchInterval: *f.watchInterval,
		DiffFile:      *f.diffFile,
		Deep:          *f.deep,
		Quick:         *f.quick,
		Traversal:     *f.traverse,
		SSRF:          *f.ssrf,
		Pollute:       *f.pollute,
		Desync:        *f.desync,
		ProtoFuzz:     *f.protoFuzz,
		RaceProbe:     *f.raceProbe,
		Exhaust:       *f.exhaust,
		RugPull:       *f.rugPull,
		TokenLeak:     *f.tokenLeak,
		Sampling:      *f.sampling,
		SideChannel:   *f.sideChannel,
		ResTraversal:  *f.resTraversal,
		PromptAudit:   *f.promptAudit,
	}
}

func parseArgs(argsStr string) []string {
	if argsStr == "" {
		return nil
	}
	return strings.Split(argsStr, ",")
}
