package client

import (
	"context"
	"testing"
)

func TestProcessTransportRoundTrip(t *testing.T) {
	transport, err := NewProcessTransport(context.Background(), "cat", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := JSONRPCMessage{JSONRPC: "2.0", Method: "ping"}
	if err := transport.Send(msg); err != nil {
		t.Fatalf("unexpected send error: %v", err)
	}

	resp, err := transport.Receive()
	if err != nil {
		t.Fatalf("unexpected receive error: %v", err)
	}
	if resp.Method != "ping" {
		t.Errorf("expected method ping, got %s", resp.Method)
	}

	if err := transport.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestProcessTransportStartFailure(t *testing.T) {
	_, err := NewProcessTransport(context.Background(), "mcpwnMissingBinary", nil)
	if err == nil {
		t.Fatal("expected start failure for missing binary")
	}
}
