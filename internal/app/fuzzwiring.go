package app

import (
	"fmt"
	"os"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/fuzzer"
)

const autoPayloadsDirectory = "mcpwn.d"

func newFuzzEngine(caller fuzzer.ToolCaller, cfg Config) (*fuzzer.Engine, error) {
	payloads := fuzzer.BuiltinPayloads()
	paths := fuzzPayloadPaths(cfg)
	if len(paths) > 0 {
		loaded, err := fuzzer.LoadPayloadFiles(paths...)
		if err != nil {
			return nil, err
		}
		for _, warning := range loaded.Warnings {
			fmt.Fprintf(os.Stderr, "mcpwn: %s\n", warning)
		}
		payloads = append(payloads, loaded.Payloads...)
	}
	return fuzzer.NewEngine(caller, fuzzer.Options{Timeout: cfg.FuzzTimeout, Payloads: payloads})
}

func fuzzPayloadPaths(cfg Config) []string {
	var paths []string
	if cfg.Payloads != "" {
		paths = append(paths, cfg.Payloads)
	}
	if info, err := os.Stat(autoPayloadsDirectory); err == nil && info.IsDir() {
		paths = append(paths, autoPayloadsDirectory)
	}
	return paths
}

func targetHint(cfg Config) string {
	if cfg.TransportType == "sse" {
		return cfg.URL
	}
	if len(cfg.Args) == 0 {
		return cfg.Command
	}
	return cfg.Command + " " + strings.Join(cfg.Args, " ")
}
