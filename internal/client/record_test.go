package client

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

type fakeTransport struct {
	responses []JSONRPCMessage
	index     int
	closed    bool
}

func (f *fakeTransport) Send(JSONRPCMessage) error {
	return nil
}

func (f *fakeTransport) Receive() (JSONRPCMessage, error) {
	if f.index >= len(f.responses) {
		return JSONRPCMessage{}, bytes.ErrTooLarge
	}
	msg := f.responses[f.index]
	f.index++
	return msg, nil
}

func (f *fakeTransport) Close() error {
	f.closed = true
	return nil
}

type closableBuffer struct {
	bytes.Buffer
	closed bool
}

func (b *closableBuffer) Close() error {
	b.closed = true
	return nil
}

func TestRecordingTransportWritesEntries(t *testing.T) {
	inner := &fakeTransport{responses: []JSONRPCMessage{
		{JSONRPC: "2.0", ID: json.RawMessage("1"), Result: json.RawMessage(`{"ok":true}`)},
	}}
	sink := &closableBuffer{}
	recorder := NewRecordingTransport(inner, sink)

	if err := recorder.Send(JSONRPCMessage{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "initialize"}); err != nil {
		t.Fatalf("send failed: %v", err)
	}
	if _, err := recorder.Receive(); err != nil {
		t.Fatalf("receive failed: %v", err)
	}
	if err := recorder.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(sink.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("expected 2 transcript lines, got %d", len(lines))
	}
	var requestEntry RecordEntry
	if err := json.Unmarshal(lines[0], &requestEntry); err != nil {
		t.Fatalf("request entry parsing failed: %v", err)
	}
	if requestEntry.Direction != "request" {
		t.Errorf("expected request direction, got %s", requestEntry.Direction)
	}
	if requestEntry.Time.IsZero() {
		t.Error("expected non-zero timestamp")
	}
	var responseEntry RecordEntry
	if err := json.Unmarshal(lines[1], &responseEntry); err != nil {
		t.Fatalf("response entry parsing failed: %v", err)
	}
	if responseEntry.Direction != "response" {
		t.Errorf("expected response direction, got %s", responseEntry.Direction)
	}
	if !inner.closed {
		t.Error("expected inner transport closed")
	}
	if !sink.closed {
		t.Error("expected sink closed")
	}
}

func TestRecordingTransportPropagatesReceiveError(t *testing.T) {
	inner := &fakeTransport{}
	sink := &bytes.Buffer{}
	recorder := NewRecordingTransport(inner, sink)
	if _, err := recorder.Receive(); err == nil {
		t.Error("expected receive error propagation")
	}
	if sink.Len() != 0 {
		t.Error("expected no transcript write on failed receive")
	}
}

func TestRecordingTransportPassThroughWithoutSinkClose(t *testing.T) {
	inner := &fakeTransport{responses: []JSONRPCMessage{{Result: json.RawMessage(`{}`)}}}
	recorder := NewRecordingTransport(inner, &bytes.Buffer{})
	start := time.Now()
	if err := recorder.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	if !inner.closed {
		t.Error("expected inner transport closed")
	}
	if time.Since(start) > time.Second {
		t.Error("close took too long")
	}
}
