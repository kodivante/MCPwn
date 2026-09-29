package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

type Session struct {
	transport Transport
	nextID    int
}

func NewSession(transport Transport) *Session {
	return &Session{transport: transport, nextID: 1}
}

func (s *Session) request(method string, params json.RawMessage) (JSONRPCMessage, error) {
	id := json.RawMessage(strconv.Itoa(s.nextID))
	s.nextID++
	msg := JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}
	if err := s.transport.Send(msg); err != nil {
		return JSONRPCMessage{}, fmt.Errorf("request %s send failed: %w", method, err)
	}
	return s.awaitResponse(id)
}

func (s *Session) awaitResponse(id json.RawMessage) (JSONRPCMessage, error) {
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

func (s *Session) notify(method string) error {
	msg := JSONRPCMessage{JSONRPC: "2.0", Method: method}
	if err := s.transport.Send(msg); err != nil {
		return fmt.Errorf("notification %s send failed: %w", method, err)
	}
	return nil
}
