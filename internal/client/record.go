package client

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type RecordEntry struct {
	Time      time.Time       `json:"time"`
	Direction string          `json:"direction"`
	Payload   json.RawMessage `json:"payload"`
}

type RecordingTransport struct {
	inner Transport
	sink  io.Writer
	mu    sync.Mutex
}

func NewRecordingTransport(inner Transport, sink io.Writer) *RecordingTransport {
	return &RecordingTransport{inner: inner, sink: sink}
}

func (r *RecordingTransport) Send(msg JSONRPCMessage) error {
	r.write("request", msg)
	return r.inner.Send(msg)
}

func (r *RecordingTransport) Receive() (JSONRPCMessage, error) {
	msg, err := r.inner.Receive()
	if err == nil {
		r.write("response", msg)
	}
	return msg, err
}

func (r *RecordingTransport) Close() error {
	closeErr := r.inner.Close()
	closer, ok := r.sink.(io.Closer)
	if !ok {
		return closeErr
	}
	if sinkErr := closer.Close(); closeErr == nil {
		closeErr = sinkErr
	}
	return closeErr
}

func (r *RecordingTransport) write(direction string, msg JSONRPCMessage) {
	payload, err := json.Marshal(msg)
	if err != nil {
		return
	}
	entry, err := json.Marshal(RecordEntry{Time: time.Now(), Direction: direction, Payload: payload})
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.sink.Write(append(entry, '\n')); err != nil {
		return
	}
}
