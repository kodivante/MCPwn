package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type SSETransport struct {
	ctx     context.Context
	client  *http.Client
	postURL string
	reader  io.ReadCloser
	scanner *bufio.Scanner
}

type sseEvent struct {
	name string
	data string
}

func NewSSETransport(ctx context.Context, getURL string) (*SSETransport, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return nil, fmt.Errorf("sse request creation failed: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sse connection failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected sse status code: %d", resp.StatusCode)
	}

	transport := &SSETransport{
		ctx:     ctx,
		client:  httpClient,
		reader:  resp.Body,
		scanner: newProtocolScanner(resp.Body),
	}
	if err := transport.discoverEndpoint(getURL); err != nil {
		transport.Close()
		return nil, err
	}
	return transport, nil
}

func (s *SSETransport) discoverEndpoint(baseURL string) error {
	for {
		evt, err := s.nextEvent()
		if err != nil {
			return fmt.Errorf("endpoint discovery failed: %w", err)
		}
		if evt.name == "endpoint" {
			resolved, err := resolveReference(baseURL, evt.data)
			if err != nil {
				return err
			}
			s.postURL = resolved
			return nil
		}
	}
}

func resolveReference(baseURL, reference string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base url: %w", err)
	}
	ref, err := url.Parse(reference)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint reference: %w", err)
	}
	return base.ResolveReference(ref).String(), nil
}

func (s *SSETransport) nextEvent() (sseEvent, error) {
	var evt sseEvent
	for s.scanner.Scan() {
		line := s.scanner.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			evt.name = strings.TrimSpace(strings.TrimPrefix(line, "event: "))
		case strings.HasPrefix(line, "data: "):
			evt.data = strings.TrimSpace(strings.TrimPrefix(line, "data: "))
		case line == "":
			if evt.name != "" || evt.data != "" {
				return evt, nil
			}
		}
	}
	if evt.name != "" || evt.data != "" {
		return evt, nil
	}
	if err := s.scanner.Err(); err != nil {
		return sseEvent{}, fmt.Errorf("sse stream read failed: %w", err)
	}
	return sseEvent{}, io.EOF
}

func (s *SSETransport) Send(msg JSONRPCMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("message serialization failed: %w", err)
	}

	req, err := http.NewRequestWithContext(s.ctx, http.MethodPost, s.postURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("post request creation failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("post request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected post status code: %d", resp.StatusCode)
	}

	return nil
}

func (s *SSETransport) Receive() (JSONRPCMessage, error) {
	for {
		evt, err := s.nextEvent()
		if err != nil {
			return JSONRPCMessage{}, err
		}
		var msg JSONRPCMessage
		if err := json.Unmarshal([]byte(evt.data), &msg); err == nil && isRPCMessage(msg) {
			return msg, nil
		}
	}
}

func isRPCMessage(msg JSONRPCMessage) bool {
	return msg.Method != "" || msg.Result != nil || msg.Error != nil
}

func (s *SSETransport) Close() error {
	return s.reader.Close()
}
