package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSSETransportEndpointDiscovery(t *testing.T) {
	postSeen := make(chan bool, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: endpoint\ndata: /messages?sessionId=abc\n\n")
		fmt.Fprintf(w, "data: keepalive\n\n")
		fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"test\"}\n\n")
	})
	mux.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		postSeen <- r.URL.Query().Get("sessionId") == "abc"
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	transport, err := NewSSETransport(context.Background(), server.URL+"/sse")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer transport.Close()

	msg, err := transport.Receive()
	if err != nil {
		t.Fatalf("unexpected receive error: %v", err)
	}
	if msg.Method != "test" {
		t.Errorf("expected method test, got %s", msg.Method)
	}

	err = transport.Send(JSONRPCMessage{JSONRPC: "2.0", Method: "ping"})
	if err != nil {
		t.Fatalf("unexpected send error: %v", err)
	}

	select {
	case ok := <-postSeen:
		if !ok {
			t.Error("expected POST with resolved session id")
		}
	case <-time.After(2 * time.Second):
		t.Error("expected POST to resolved endpoint url")
	}
}

func TestSSETransportMissingEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"test\"}\n\n")
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	if _, err := NewSSETransport(context.Background(), server.URL+"/sse"); err == nil {
		t.Fatal("expected endpoint discovery error")
	}
}

func TestSSETransportBadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	if _, err := NewSSETransport(context.Background(), server.URL); err == nil {
		t.Fatal("expected status code error")
	}
}

func TestResolveReference(t *testing.T) {
	tests := []struct {
		name      string
		baseURL   string
		reference string
		want      string
	}{
		{
			name:      "relative path",
			baseURL:   "http://localhost:8080/sse",
			reference: "/messages?sessionId=abc",
			want:      "http://localhost:8080/messages?sessionId=abc",
		},
		{
			name:      "absolute url",
			baseURL:   "http://localhost:8080/sse",
			reference: "http://other:9000/messages",
			want:      "http://other:9000/messages",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveReference(tc.baseURL, tc.reference)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("expected %s, got %s", tc.want, got)
			}
		})
	}
}
