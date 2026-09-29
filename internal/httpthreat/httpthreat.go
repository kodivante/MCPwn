package httpthreat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/client"
)

const defaultTimeout = 10 * time.Second

type Options struct {
	AuthHeader string
	Timeout    time.Duration
}

type Engine struct {
	url        string
	authHeader string
	client     *http.Client
}

func NewEngine(url string, options Options) *Engine {
	if options.Timeout <= 0 {
		options.Timeout = defaultTimeout
	}
	return &Engine{
		url:        url,
		authHeader: options.AuthHeader,
		client:     &http.Client{Timeout: options.Timeout},
	}
}

type probeResponse struct {
	statusCode int
	sessionID  string
	message    client.JSONRPCMessage
	hasMessage bool
}

func (e *Engine) authHeaders() map[string]string {
	if e.authHeader == "" {
		return map[string]string{}
	}
	return map[string]string{"Authorization": e.authHeader}
}

func (e *Engine) post(body []byte, headers map[string]string) (probeResponse, error) {
	req, err := http.NewRequest(http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return probeResponse{}, fmt.Errorf("probe request creation failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return probeResponse{}, fmt.Errorf("probe request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return probeResponse{}, fmt.Errorf("probe response read failed: %w", err)
	}
	outcome := probeResponse{
		statusCode: resp.StatusCode,
		sessionID:  resp.Header.Get("Mcp-Session-Id"),
	}
	outcome.message, outcome.hasMessage = parseResponsePayload(data, resp.Header.Get("Content-Type"))
	return outcome, nil
}

func parseResponsePayload(data []byte, contentType string) (client.JSONRPCMessage, bool) {
	payload := data
	if strings.Contains(contentType, "text/event-stream") {
		payload = extractFirstEventData(data)
	}
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return client.JSONRPCMessage{}, false
	}
	if trimmed[0] == '[' {
		return parseBatchResponse(trimmed)
	}
	var msg client.JSONRPCMessage
	if err := json.Unmarshal(trimmed, &msg); err != nil {
		return client.JSONRPCMessage{}, false
	}
	if msg.Method != "" {
		return client.JSONRPCMessage{}, false
	}
	return msg, true
}

func parseBatchResponse(trimmed []byte) (client.JSONRPCMessage, bool) {
	var batch []client.JSONRPCMessage
	if err := json.Unmarshal(trimmed, &batch); err != nil || len(batch) == 0 {
		return client.JSONRPCMessage{}, false
	}
	return batch[0], true
}

func extractFirstEventData(data []byte) []byte {
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "data: ") {
			return []byte(strings.TrimSpace(strings.TrimPrefix(line, "data: ")))
		}
	}
	return nil
}

func initializePayload(id int) []byte {
	return fmt.Appendf(nil, `{"jsonrpc":"2.0","id":%d,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"MCPwn http probe","version":"1.0.0"}}}`, id)
}

func toolsListPayload(id int) []byte {
	return fmt.Appendf(nil, `{"jsonrpc":"2.0","id":%d,"method":"tools/list"}`, id)
}
