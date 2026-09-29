package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const sessionUnresponsiveMessage = "session marked unresponsive after exceeding the request timeout"

var errSessionUnresponsive = errors.New(sessionUnresponsiveMessage)

type Session struct {
	transport Transport
	nextID    int
	mu        sync.Mutex
	poisoned  atomic.Bool
	timeout   time.Duration
}

func NewSession(transport Transport) *Session {
	return &Session{transport: transport, nextID: 1}
}

func (s *Session) SetRequestTimeout(timeout time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timeout = timeout
}

func (s *Session) request(method string, params json.RawMessage) (JSONRPCMessage, error) {
	id, err := s.reserveID()
	if err != nil {
		return JSONRPCMessage{}, fmt.Errorf("request %s failed: %w", method, err)
	}
	msg := JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}
	if err := s.transport.Send(msg); err != nil {
		return JSONRPCMessage{}, fmt.Errorf("request %s send failed: %w", method, err)
	}
	response, err := s.awaitResponse(id)
	if err != nil {
		return JSONRPCMessage{}, fmt.Errorf("request %s failed: %w", method, err)
	}
	return response, nil
}

func (s *Session) reserveID() (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned.Load() {
		return nil, errSessionUnresponsive
	}
	id := json.RawMessage(strconv.Itoa(s.nextID))
	s.nextID++
	return id, nil
}

func (s *Session) awaitResponse(id json.RawMessage) (JSONRPCMessage, error) {
	if s.poisoned.Load() {
		return JSONRPCMessage{}, errSessionUnresponsive
	}
	s.mu.Lock()
	timeout := s.timeout
	s.mu.Unlock()
	if timeout > 0 {
		return s.awaitResponseBounded(id, timeout)
	}
	return s.awaitResponseBlocking(id)
}

func (s *Session) awaitResponseBlocking(id json.RawMessage) (JSONRPCMessage, error) {
	for {
		msg, err := s.transport.Receive()
		if err != nil {
			return JSONRPCMessage{}, fmt.Errorf("response read failed: %w", err)
		}
		if len(msg.ID) == 0 || !bytes.Equal(msg.ID, id) {
			continue
		}
		if msg.Error != nil {
			return JSONRPCMessage{}, &RPCError{Code: msg.Error.Code, Message: msg.Error.Message}
		}
		return msg, nil
	}
}

func (s *Session) awaitResponseBounded(id json.RawMessage, timeout time.Duration) (JSONRPCMessage, error) {
	deadline := time.After(timeout)
	for {
		outcome := make(chan readOutcome, 1)
		go func() {
			msg, err := s.transport.Receive()
			outcome <- readOutcome{msg: msg, err: err}
		}()
		select {
		case res := <-outcome:
			if res.err != nil {
				return JSONRPCMessage{}, fmt.Errorf("response read failed: %w", res.err)
			}
			if len(res.msg.ID) == 0 || !bytes.Equal(res.msg.ID, id) {
				continue
			}
			if res.msg.Error != nil {
				return JSONRPCMessage{}, &RPCError{Code: res.msg.Error.Code, Message: res.msg.Error.Message}
			}
			return res.msg, nil
		case <-deadline:
			s.poisoned.Store(true)
			return JSONRPCMessage{}, errSessionUnresponsive
		}
	}
}

type readOutcome struct {
	msg JSONRPCMessage
	err error
}

func (s *Session) notify(method string) error {
	msg := JSONRPCMessage{JSONRPC: "2.0", Method: method}
	if err := s.transport.Send(msg); err != nil {
		return fmt.Errorf("notification %s send failed: %w", method, err)
	}
	return nil
}
