package testutil

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

const resourcesPayload = `{"resources":[{"uri":"file:///workspace/data.txt","name":"data","description":"workspace data"}]}`

type readResourceParams struct {
	URI string `json:"uri"`
}

type resourceContent struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type readResourceResult struct {
	Contents []resourceContent `json:"contents"`
}

func PipeResourceReflecting() net.Conn {
	clientConn, serverConn := net.Pipe()
	go serveResourceReflecting(serverConn)
	return clientConn
}

func PipeResourceSafe() net.Conn {
	clientConn, serverConn := net.Pipe()
	go serveResourceSafe(serverConn)
	return clientConn
}

func serveResourceReflecting(conn net.Conn) {
	defer conn.Close()
	_ = serveResourceRequests(conn, true)
}

func serveResourceSafe(conn net.Conn) {
	defer conn.Close()
	_ = serveResourceRequests(conn, false)
}

func serveResourceRequests(conn net.Conn, allowAnyPath bool) error {
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		var req mockRequest
		if json.Unmarshal(scanner.Bytes(), &req) != nil {
			continue
		}
		if err := handleResourceRequest(conn, req, allowAnyPath); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func handleResourceRequest(conn net.Conn, req mockRequest, allowAnyPath bool) error {
	switch req.Method {
	case "initialize":
		return writeMessage(conn, mockResponse{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(initializeResult)})
	case "resources/list":
		return writeMessage(conn, mockResponse{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(resourcesPayload)})
	case "resources/read":
		return handleResourceRead(conn, req, allowAnyPath)
	}
	return nil
}

func handleResourceRead(conn net.Conn, req mockRequest, allowAnyPath bool) error {
	var params readResourceParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return writeMessage(conn, mockResponse{JSONRPC: "2.0", ID: req.ID, Error: &mockError{Code: -32602, Message: "invalid params"}})
	}

	if allowAnyPath {
		if content, err := readAnyFile(params.URI); err == nil {
			result := readResourceResult{Contents: []resourceContent{{URI: params.URI, MimeType: "text/plain", Text: content}}}
			return writeResourceResult(conn, req, result)
		}
	}

	if params.URI == "file:///workspace/data.txt" {
		result := readResourceResult{Contents: []resourceContent{{URI: params.URI, MimeType: "text/plain", Text: "safe workspace content"}}}
		return writeResourceResult(conn, req, result)
	}
	return writeMessage(conn, mockResponse{JSONRPC: "2.0", ID: req.ID, Error: &mockError{Code: -32002, Message: "resource not found"}})
}

func readAnyFile(uri string) (string, error) {
	path := strings.TrimPrefix(uri, "file://")
	path = strings.TrimPrefix(path, "file:")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("resource read failed: %w", err)
	}
	return string(data), nil
}

func writeResourceResult(conn net.Conn, req mockRequest, result readResourceResult) error {
	encoded, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("resource result encoding failed: %w", err)
	}
	return writeMessage(conn, mockResponse{JSONRPC: "2.0", ID: req.ID, Result: encoded})
}
