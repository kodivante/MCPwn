package app

import (
	"context"
	"fmt"
	"os"
	"time"
)

const defaultWatchInterval = 30 * time.Second

func watchLoop(ctx context.Context, cfg Config, factory transportFactory) (int, error) {
	interval := cfg.WatchInterval
	if interval <= 0 {
		interval = defaultWatchInterval
	}
	onceCfg := cfg
	onceCfg.Watch = false

	code, err := runOnce(ctx, onceCfg, factory)
	if err != nil {
		if ctx.Err() != nil {
			return 1, nil
		}
		return 1, err
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return code, nil
		case <-ticker.C:
			clearScreen()
			fmt.Fprintf(os.Stdout, "mcpwn: refreshing (interval %s)\n", interval)
			code, err = runOnce(ctx, onceCfg, factory)
			if err != nil {
				if ctx.Err() != nil {
					return code, nil
				}
				return 1, err
			}
		}
	}
}

func runOnce(ctx context.Context, cfg Config, factory transportFactory) (int, error) {
	if cfg.Timeout <= 0 {
		return runWith(ctx, cfg, factory)
	}
	runCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	return runWith(runCtx, cfg, factory)
}

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}
