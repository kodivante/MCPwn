package client

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
)

type ProcessTransport struct {
	*StreamTransport
	cmd *exec.Cmd
}

func NewProcessTransport(ctx context.Context, command string, args []string) (*ProcessTransport, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe failed: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("stdout pipe failed: %w", err), stdin.Close())
	}

	if err := cmd.Start(); err != nil {
		return nil, errors.Join(fmt.Errorf("process start failed: %w", err), stdin.Close(), stdout.Close())
	}

	stream := NewStreamTransport(stdout, stdin)
	return &ProcessTransport{
		StreamTransport: stream,
		cmd:             cmd,
	}, nil
}

func (p *ProcessTransport) Close() error {
	errStream := p.StreamTransport.Close()
	errWait := p.cmd.Wait()
	if errWait != nil {
		return fmt.Errorf("process wait failed: %w", errWait)
	}
	if errStream != nil {
		return errStream
	}
	return nil
}
