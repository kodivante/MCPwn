package testutil

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
)

const toolsPayload = `{"tools":[{"name":"system_exec","inputSchema":{"type":"object","properties":{"cmd":{"type":"string"}}}}]}`

const (
	initializeResult = `{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"mock","version":"1.0.0"}}`
	callToolResult   = `{"content":[{"type":"text","text":"echo mcpwn_probe"}]}`
)

type mockRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type mockError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mockResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *mockError      `json:"error,omitempty"`
}

type mockCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type mockCallArguments struct {
	Cmd string `json:"cmd"`
}

type mockContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mockToolResult struct {
	Content []mockContent `json:"content"`
	IsError bool          `json:"isError"`
}

func Pipe(toolsPayload string) net.Conn {
	clientConn, serverConn := net.Pipe()
	go ServeConn(serverConn, toolsPayload)
	return clientConn
}

func PipeReflecting(toolsPayload string) net.Conn {
	clientConn, serverConn := net.Pipe()
	go serveReflecting(serverConn, toolsPayload)
	return clientConn
}

func ServeConn(conn net.Conn, toolsPayload string) {
	defer conn.Close()
	_ = serveRequests(conn, toolsPayload, false)
}

func serveReflecting(conn net.Conn, toolsPayload string) {
	defer conn.Close()
	_ = serveRequests(conn, toolsPayload, true)
}

func serveRequests(conn net.Conn, toolsPayload string, reflect bool) error {
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		var req mockRequest
		if json.Unmarshal(scanner.Bytes(), &req) != nil {
			continue
		}
		if err := handleMockRequest(conn, req, toolsPayload, reflect); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func handleMockRequest(conn net.Conn, req mockRequest, toolsPayload string, reflect bool) error {
	switch req.Method {
	case "initialize":
		return writeMessage(conn, mockResponse{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(initializeResult)})
	case "tools/list":
		notification := mockResponse{JSONRPC: "2.0", Method: "notifications/message"}
		if err := writeMessage(conn, notification); err != nil {
			return err
		}
		return writeMessage(conn, mockResponse{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(toolsPayload)})
	case "tools/call":
		result := json.RawMessage(callToolResult)
		if reflect {
			result = json.RawMessage(reflectCallResult(req.Params))
		}
		return writeMessage(conn, mockResponse{JSONRPC: "2.0", ID: req.ID, Result: result})
	case "error":
		return writeMessage(conn, mockResponse{JSONRPC: "2.0", ID: req.ID, Error: &mockError{Code: -32601, Message: "method not found"}})
	}
	if req.ID == nil {
		return nil
	}
	return writeMessage(conn, mockResponse{JSONRPC: "2.0", ID: req.ID, Error: &mockError{Code: -32601, Message: "method not found"}})
}

func reflectCallResult(params json.RawMessage) string {
	var call mockCallParams
	if err := json.Unmarshal(params, &call); err != nil {
		return callToolResult
	}
	var arguments mockCallArguments
	if err := json.Unmarshal(call.Arguments, &arguments); err != nil {
		return callToolResult
	}
	data, err := json.Marshal(mockToolResult{Content: []mockContent{{Type: "text", Text: arguments.Cmd}}})
	if err != nil {
		return callToolResult
	}
	return string(data)
}

func writeMessage(conn net.Conn, payload mockResponse) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("mock message serialization failed: %w", err)
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("mock message write failed: %w", err)
	}
	return nil
}
