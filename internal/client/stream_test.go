package client

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
)

type mockReadWriteCloser struct {
	readBuffer  []byte
	writeBuffer []byte
	readIndex   int
	closed      bool
}

func (m *mockReadWriteCloser) Read(p []byte) (n int, err error) {
	if m.closed {
		return 0, io.EOF
	}
	if m.readIndex >= len(m.readBuffer) {
		return 0, io.EOF
	}
	n = copy(p, m.readBuffer[m.readIndex:])
	m.readIndex += n
	return n, nil
}

func (m *mockReadWriteCloser) Write(p []byte) (n int, err error) {
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	m.writeBuffer = append(m.writeBuffer, p...)
	return len(p), nil
}

func (m *mockReadWriteCloser) Close() error {
	if m.closed {
		return io.ErrClosedPipe
	}
	m.closed = true
	return nil
}

func TestStreamTransportSendReceive(t *testing.T) {
	inputMsg := `{"jsonrpc":"2.0","method":"test","params":{}}` + "\n"
	mock := &mockReadWriteCloser{readBuffer: []byte(inputMsg)}

	transport := NewStreamTransport(mock, mock)

	msg, err := transport.Receive()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Method != "test" {
		t.Errorf("expected method test, got %s", msg.Method)
	}

	err = transport.Send(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sentMsg JSONRPCMessage
	if err := json.Unmarshal(mock.writeBuffer, &sentMsg); err != nil {
		t.Fatalf("invalid sent message: %v", err)
	}
	if sentMsg.Method != "test" {
		t.Errorf("expected method test in sent message, got %s", sentMsg.Method)
	}
}

func TestStreamTransportReceiveEOF(t *testing.T) {
	mock := &mockReadWriteCloser{}
	transport := NewStreamTransport(mock, mock)
	if _, err := transport.Receive(); err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestStreamTransportCloseError(t *testing.T) {
	mock := &mockReadWriteCloser{closed: true}
	transport := NewStreamTransport(mock, mock)
	if err := transport.Close(); err == nil {
		t.Fatal("expected close error on already closed pipes")
	}
}

func TestStreamTransportLargeMessage(t *testing.T) {
	bigMethod := strings.Repeat("a", 200*1024)
	input := `{"jsonrpc":"2.0","method":"` + bigMethod + `"}` + "\n"
	mock := &mockReadWriteCloser{readBuffer: []byte(input)}

	transport := NewStreamTransport(mock, mock)

	msg, err := transport.Receive()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msg.Method) != 200*1024 {
		t.Errorf("expected full payload, got %d bytes", len(msg.Method))
	}
}

func TestJSONRPCMessageID(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		wantID  string
	}{
		{name: "numeric id", payload: `{"jsonrpc":"2.0","id":1,"result":{}}`, wantID: "1"},
		{name: "string id", payload: `{"jsonrpc":"2.0","id":"abc","result":{}}`, wantID: `"abc"`},
		{name: "notification without id", payload: `{"jsonrpc":"2.0","method":"ping"}`, wantID: ""},
		{name: "error response", payload: `{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"nope"}}`, wantID: "2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var msg JSONRPCMessage
			if err := json.Unmarshal([]byte(tc.payload), &msg); err != nil {
				t.Fatalf("unexpected unmarshal error: %v", err)
			}
			if string(msg.ID) != tc.wantID {
				t.Errorf("expected id %s, got %s", tc.wantID, msg.ID)
			}
		})
	}
}
