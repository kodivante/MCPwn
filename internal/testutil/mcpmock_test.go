package testutil

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestPipeServesInitialize(t *testing.T) {
	conn := Pipe(toolsPayload)
	defer conn.Close()

	request := `{"jsonrpc":"2.0","id":7,"method":"initialize"}` + "\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}

	payload, err := readMockResponse(conn)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if string(payload.ID) != "7" {
		t.Errorf("expected id 7, got %s", payload.ID)
	}
	if !strings.Contains(string(payload.Result), "protocolVersion") {
		t.Errorf("expected initialize result, got %s", payload.Result)
	}
}

func TestPipeServesError(t *testing.T) {
	conn := Pipe(toolsPayload)
	defer conn.Close()

	request := `{"jsonrpc":"2.0","id":1,"method":"error"}` + "\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}

	payload, err := readMockResponse(conn)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if payload.Error == nil || payload.Error.Code != -32601 {
		t.Errorf("expected rpc error, got %+v", payload.Error)
	}
}

func TestPipeServesCallTool(t *testing.T) {
	conn := Pipe(toolsPayload)
	defer conn.Close()

	request := `{"jsonrpc":"2.0","id":3,"method":"tools/call"}` + "\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}

	payload, err := readMockResponse(conn)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if string(payload.ID) != "3" {
		t.Errorf("expected id 3, got %s", payload.ID)
	}
	if !strings.Contains(string(payload.Result), "content") {
		t.Errorf("expected call tool result, got %s", payload.Result)
	}
}

func TestPipeReflectingCallTool(t *testing.T) {
	conn := PipeReflecting(toolsPayload)
	defer conn.Close()

	request := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"system_exec","arguments":{"cmd":"echo reflected_marker"}}}` + "\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}

	payload, err := readMockResponse(conn)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if !strings.Contains(string(payload.Result), "echo reflected_marker") {
		t.Errorf("expected reflected command in result, got %s", payload.Result)
	}
}

func readMockResponse(conn net.Conn) (mockResponse, error) {
	var payload mockResponse
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return payload, fmt.Errorf("mock response read failed: %w", err)
	}
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		return payload, fmt.Errorf("mock response parsing failed: %w", err)
	}
	return payload, nil
}
