package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/kodivante/MCPwn/v3/internal/client"
)

func connect(ctx context.Context, cfg Config) (client.Transport, error) {
	switch cfg.TransportType {
	case "stdio":
		return connectStdio(ctx, cfg)
	case "sse":
		return connectSSE(ctx, cfg)
	default:
		return nil, fmt.Errorf("invalid transport type: %s", cfg.TransportType)
	}
}

func connectStdio(ctx context.Context, cfg Config) (client.Transport, error) {
	if cfg.Command == "" {
		return nil, errors.New("--command is required for stdio transport")
	}
	return client.NewProcessTransport(ctx, cfg.Command, cfg.Args)
}

func connectSSE(ctx context.Context, cfg Config) (client.Transport, error) {
	if cfg.URL == "" {
		return nil, errors.New("--url is required for sse transport")
	}
	return client.NewSSETransport(ctx, cfg.URL)
}
