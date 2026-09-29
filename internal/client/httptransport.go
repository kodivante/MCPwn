package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const defaultHTTPTimeout = 30 * time.Second

type HTTPOptions struct {
	AuthHeader string
	Timeout    time.Duration
}

type HTTPTransport struct {
	ctx        context.Context
	client     *http.Client
	url        string
	authHeader string
	sessionID  string
	mu         sync.Mutex
	cond       *sync.Cond
	pending    []JSONRPCMessage
	closed     bool
}

func NewHTTPTransport(ctx context.Context, endpoint string, options HTTPOptions) (*HTTPTransport, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("http transport requires an endpoint url")
	}
	if options.Timeout <= 0 {
		options.Timeout = defaultHTTPTimeout
	}
	transport := &HTTPTransport{
		ctx:        ctx,
		client:     &http.Client{Timeout: options.Timeout},
		url:        endpoint,
		authHeader: options.AuthHeader,
	}
	transport.cond = sync.NewCond(&transport.mu)
	return transport, nil
}

func (t *HTTPTransport) Send(msg JSONRPCMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("http message serialization failed: %w", err)
	}
	req, err := http.NewRequestWithContext(t.ctx, http.MethodPost, t.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("http request creation failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if t.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", t.sessionID)
	}
	if t.authHeader != "" {
		req.Header.Set("Authorization", t.authHeader)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected http status code: %d", resp.StatusCode)
	}
	if sessionID := resp.Header.Get("Mcp-Session-Id"); sessionID != "" {
		t.sessionID = sessionID
	}
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/event-stream") {
		return t.consumeStream(resp.Body, msg.ID)
	}
	return t.consumeJSON(resp.Body)
}

func (t *HTTPTransport) consumeJSON(body io.Reader) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("http response read failed: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var msg JSONRPCMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return fmt.Errorf("http response parsing failed: %w", err)
	}
	if !isRPCMessage(msg) {
		return nil
	}
	t.push(msg)
	return nil
}

func (t *HTTPTransport) consumeStream(body io.Reader, requestID json.RawMessage) error {
	scanner := newProtocolScanner(body)
	var dataLines []string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "data: "):
			dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))
		case line == "":
			if len(dataLines) == 0 {
				continue
			}
			if t.absorbStreamPayload(dataLines, requestID) {
				return nil
			}
			dataLines = nil
		}
	}
	if len(dataLines) > 0 {
		t.absorbStreamPayload(dataLines, requestID)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("http stream read failed: %w", err)
	}
	return nil
}

func (t *HTTPTransport) absorbStreamPayload(dataLines []string, requestID json.RawMessage) bool {
	payload := strings.Join(dataLines, "\n")
	var msg JSONRPCMessage
	if err := json.Unmarshal([]byte(payload), &msg); err != nil || !isRPCMessage(msg) {
		return false
	}
	t.push(msg)
	return len(requestID) > 0 && bytes.Equal(msg.ID, requestID)
}

func (t *HTTPTransport) push(msg JSONRPCMessage) {
	t.mu.Lock()
	t.pending = append(t.pending, msg)
	t.mu.Unlock()
	t.cond.Broadcast()
}

func (t *HTTPTransport) Receive() (JSONRPCMessage, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for len(t.pending) == 0 {
		if t.closed {
			return JSONRPCMessage{}, fmt.Errorf("http transport closed")
		}
		if err := t.ctx.Err(); err != nil {
			return JSONRPCMessage{}, fmt.Errorf("http transport cancelled: %w", err)
		}
		t.cond.Wait()
	}
	msg := t.pending[0]
	t.pending = t.pending[1:]
	return msg, nil
}

func (t *HTTPTransport) Close() error {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	t.cond.Broadcast()
	if t.sessionID == "" || t.ctx.Err() != nil {
		return nil
	}
	req, err := http.NewRequestWithContext(t.ctx, http.MethodDelete, t.url, nil)
	if err != nil {
		return fmt.Errorf("http session termination request failed: %w", err)
	}
	req.Header.Set("Mcp-Session-Id", t.sessionID)
	if t.authHeader != "" {
		req.Header.Set("Authorization", t.authHeader)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("http session termination failed: %w", err)
	}
	defer resp.Body.Close()
	return nil
}
