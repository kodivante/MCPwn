package client

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/testutil"
)

const sessionToolsPayload = `{"tools":[{"name":"system_exec","inputSchema":{"type":"object","properties":{"cmd":{"type":"string"}}}}]}`

type callToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type callToolResult struct {
	Content []callToolContent `json:"content"`
}

func TestSessionInitializeAndListTools(t *testing.T) {
	conn := testutil.Pipe(sessionToolsPayload)
	defer conn.Close()

	session := NewSession(NewStreamTransport(conn, conn))

	if err := session.Initialize(); err != nil {
		t.Fatalf("unexpected initialize error: %v", err)
	}

	tools, err := session.ListTools()
	if err != nil {
		t.Fatalf("unexpected list tools error: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "system_exec" {
		t.Fatalf("unexpected tools: %+v", tools)
	}
}

func TestSessionCallTool(t *testing.T) {
	conn := testutil.Pipe(sessionToolsPayload)
	defer conn.Close()

	session := NewSession(NewStreamTransport(conn, conn))
	if err := session.Initialize(); err != nil {
		t.Fatalf("unexpected initialize error: %v", err)
	}

	result, err := session.CallTool("system_exec", json.RawMessage(`{"cmd":"echo probe"}`))
	if err != nil {
		t.Fatalf("unexpected call tool error: %v", err)
	}

	var payload callToolResult
	if err := json.Unmarshal(result, &payload); err != nil {
		t.Fatalf("unexpected result parsing error: %v", err)
	}
	if len(payload.Content) != 1 || payload.Content[0].Text != "echo mcpwn_probe" {
		t.Errorf("unexpected call result: %+v", payload.Content)
	}
}

func TestSessionRPCError(t *testing.T) {
	conn := testutil.Pipe(sessionToolsPayload)
	defer conn.Close()

	session := NewSession(NewStreamTransport(conn, conn))

	_, err := session.request("error", nil)
	if err == nil {
		t.Fatal("expected rpc error")
	}
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) {
		t.Fatalf("expected *RPCError, got %T: %v", err, err)
	}
	if rpcErr.Code != -32601 {
		t.Errorf("expected code -32601, got %d", rpcErr.Code)
	}
	if rpcErr.Error() == "" {
		t.Error("expected non-empty rpc error message")
	}
}

func TestSessionTransportFailure(t *testing.T) {
	mock := &mockReadWriteCloser{}
	session := NewSession(NewStreamTransport(mock, mock))

	err := session.Initialize()
	if err == nil {
		t.Fatal("expected transport failure")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF in error chain, got %v", err)
	}
}

type hangingTransport struct {
	done chan struct{}
}

func (h *hangingTransport) Send(JSONRPCMessage) error {
	return nil
}

func (h *hangingTransport) Receive() (JSONRPCMessage, error) {
	<-h.done
	return JSONRPCMessage{}, errors.New("transport closed")
}

func (h *hangingTransport) Close() error {
	close(h.done)
	return nil
}

func TestSessionTimeoutPoisonsUnresponsiveServer(t *testing.T) {
	transport := &hangingTransport{done: make(chan struct{})}
	defer transport.Close()
	session := NewSession(transport)
	session.SetRequestTimeout(50 * time.Millisecond)

	start := time.Now()
	if _, err := session.ListTools(); err == nil {
		t.Fatal("expected timeout error on unresponsive server")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("expected bounded wait, took %s", elapsed)
	}

	secondStart := time.Now()
	_, err := session.ListTools()
	if err == nil {
		t.Fatal("expected poisoned session to reject further requests")
	}
	if !strings.Contains(err.Error(), "unresponsive") {
		t.Errorf("expected unresponsive error, got %v", err)
	}
	if elapsed := time.Since(secondStart); elapsed > 100*time.Millisecond {
		t.Errorf("expected instant rejection after poisoning, took %s", elapsed)
	}
}

func TestSessionWithoutTimeoutStaysUnbounded(t *testing.T) {
	transport := &hangingTransport{done: make(chan struct{})}
	session := NewSession(transport)
	if session.poisoned.Load() {
		t.Error("session must not start poisoned")
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		transport.Close()
	}()
	if _, err := session.ListTools(); err == nil {
		t.Fatal("expected error after transport close")
	}
	if session.poisoned.Load() {
		t.Error("blocking sessions must not poison on transport errors")
	}
}
