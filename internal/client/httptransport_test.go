package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const httpToolsPayload = `{"tools":[{"name":"readFile","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}]}`

type streamableServer struct {
	mu          sync.Mutex
	sessionSeen bool
	deleteSeen  bool
}

func (s *streamableServer) handler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		s.mu.Lock()
		s.deleteSeen = true
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var msg JSONRPCMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch msg.Method {
	case "initialize":
		w.Header().Set("Mcp-Session-Id", "sess-42")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"mock","version":"1.0"}}}`, msg.ID)
	case "tools/list":
		if r.Header.Get("Mcp-Session-Id") == "sess-42" {
			s.mu.Lock()
			s.sessionSeen = true
			s.mu.Unlock()
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}\n\n", msg.ID, httpToolsPayload)
	default:
		if len(msg.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"method not found"}}`, msg.ID)
	}
}

func newStreamableTestServer(t *testing.T) (*httptest.Server, *streamableServer) {
	t.Helper()
	state := &streamableServer{}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	t.Cleanup(server.Close)
	return server, state
}

func TestHTTPTransportSessionFlow(t *testing.T) {
	server, state := newStreamableTestServer(t)
	transport, err := NewHTTPTransport(context.Background(), server.URL, HTTPOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("transport creation failed: %v", err)
	}
	session := NewSession(transport)
	if err := session.Initialize(); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}
	tools, err := session.ListTools()
	if err != nil {
		t.Fatalf("tools/list failed: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "readFile" {
		t.Fatalf("unexpected tools: %+v", tools)
	}
	if err := transport.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.sessionSeen {
		t.Error("expected session id header on tools/list request")
	}
	if !state.deleteSeen {
		t.Error("expected session termination via DELETE")
	}
}

func TestHTTPTransportReceiveBlocksUntilPush(t *testing.T) {
	transport := &HTTPTransport{ctx: context.Background()}
	transport.cond = sync.NewCond(&transport.mu)
	done := make(chan JSONRPCMessage, 1)
	go func() {
		msg, err := transport.Receive()
		if err == nil {
			done <- msg
		}
	}()
	time.Sleep(50 * time.Millisecond)
	transport.push(JSONRPCMessage{ID: json.RawMessage("7"), Result: json.RawMessage(`{"ok":true}`)})
	select {
	case msg := <-done:
		if string(msg.ID) != "7" {
			t.Errorf("unexpected message id %s", msg.ID)
		}
	case <-time.After(2 * time.Second):
		t.Error("receive did not unblock after push")
	}
}

func TestHTTPTransportReceiveAfterClose(t *testing.T) {
	transport := &HTTPTransport{ctx: context.Background()}
	transport.cond = sync.NewCond(&transport.mu)
	if err := transport.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	if _, err := transport.Receive(); err == nil {
		t.Error("expected error receiving from closed transport")
	}
}

func TestHTTPTransportReceiveCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport := &HTTPTransport{ctx: ctx}
	transport.cond = sync.NewCond(&transport.mu)
	cancel()
	go transport.cond.Broadcast()
	if _, err := transport.Receive(); err == nil {
		t.Error("expected error on cancelled context")
	}
}

func TestHTTPTransportServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	transport, err := NewHTTPTransport(context.Background(), server.URL, HTTPOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("transport creation failed: %v", err)
	}
	msg := JSONRPCMessage{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "initialize"}
	if err := transport.Send(msg); err == nil {
		t.Error("expected error on 500 response")
	}
}

func TestNewHTTPTransportRequiresURL(t *testing.T) {
	if _, err := NewHTTPTransport(context.Background(), "", HTTPOptions{}); err == nil {
		t.Error("expected error for empty endpoint")
	}
}
