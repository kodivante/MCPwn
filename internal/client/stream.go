package client

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	initialBufferSize = 64 * 1024
	maxLineSize       = 1024 * 1024
)

type StreamTransport struct {
	writer  io.WriteCloser
	reader  io.ReadCloser
	scanner *bufio.Scanner
}

func newProtocolScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, initialBufferSize), maxLineSize)
	return scanner
}

func NewStreamTransport(r io.ReadCloser, w io.WriteCloser) *StreamTransport {
	return &StreamTransport{
		writer:  w,
		reader:  r,
		scanner: newProtocolScanner(r),
	}
}

func (s *StreamTransport) Send(msg JSONRPCMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("message serialization failed: %w", err)
	}
	data = append(data, '\n')
	if _, err := s.writer.Write(data); err != nil {
		return fmt.Errorf("message write failed: %w", err)
	}
	return nil
}

func (s *StreamTransport) Receive() (JSONRPCMessage, error) {
	if !s.scanner.Scan() {
		if err := s.scanner.Err(); err != nil {
			return JSONRPCMessage{}, fmt.Errorf("read failed: %w", err)
		}
		return JSONRPCMessage{}, io.EOF
	}

	var msg JSONRPCMessage
	if err := json.Unmarshal(s.scanner.Bytes(), &msg); err != nil {
		return JSONRPCMessage{}, fmt.Errorf("message parsing failed: %w", err)
	}

	return msg, nil
}

func (s *StreamTransport) Close() error {
	errW := s.writer.Close()
	errR := s.reader.Close()
	if errW != nil && !errors.Is(errW, os.ErrClosed) {
		return fmt.Errorf("writer close failed: %w", errW)
	}
	if errR != nil && !errors.Is(errR, os.ErrClosed) {
		return fmt.Errorf("reader close failed: %w", errR)
	}
	return nil
}
