package fuzzer

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"
)

func ParseDSL(data []byte) ([]Payload, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var payloads []Payload
	var current *Payload

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var err error
		switch {
		case strings.HasPrefix(line, "payload "):
			err = beginPayload(&current, line)
		case line == "}":
			err = endPayload(&current, &payloads)
		case current == nil:
			err = errors.New("unexpected content outside a payload block")
		default:
			err = assignPayloadField(current, line)
		}
		if err != nil {
			return nil, fmt.Errorf("dsl line %q: %w", line, err)
		}
	}
	if scanner.Err() != nil {
		return nil, fmt.Errorf("dsl reading failed: %w", scanner.Err())
	}
	if current != nil {
		return nil, fmt.Errorf("unterminated payload block %q", current.Name)
	}
	return payloads, nil
}

func beginPayload(current **Payload, line string) error {
	if *current != nil {
		return fmt.Errorf("nested payload block inside %q", (*current).Name)
	}
	name, err := parsePayloadName(line)
	if err != nil {
		return err
	}
	*current = &Payload{Name: name}
	return nil
}

func parsePayloadName(line string) (string, error) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "payload "))
	if !strings.HasSuffix(rest, "{") {
		return "", errors.New("payload header must end with {")
	}
	rest = strings.TrimSpace(strings.TrimSuffix(rest, "{"))
	if len(rest) < 2 || !strings.HasPrefix(rest, "\"") || !strings.HasSuffix(rest, "\"") {
		return "", errors.New("payload name must be a quoted string")
	}
	name := strings.Trim(rest, "\"")
	if name == "" {
		return "", errors.New("payload name cannot be empty")
	}
	return name, nil
}

func endPayload(current **Payload, payloads *[]Payload) error {
	if *current == nil {
		return errors.New("unexpected closing brace")
	}
	if (*current).RuleID == "" {
		return fmt.Errorf("payload %q missing rule field", (*current).Name)
	}
	if (*current).Template == "" {
		return fmt.Errorf("payload %q missing template field", (*current).Name)
	}
	*payloads = append(*payloads, **current)
	*current = nil
	return nil
}

func assignPayloadField(current *Payload, line string) error {
	key, value, err := parseAssignment(line)
	if err != nil {
		return err
	}
	switch key {
	case "rule":
		current.RuleID = value
	case "template":
		current.Template = value
	case "expect":
		current.Expect = value
	case "description":
		current.Description = value
	case "delay":
		delay, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid delay %q: %w", value, err)
		}
		current.MinDelay = delay
	default:
		return fmt.Errorf("unknown field %q", key)
	}
	return nil
}

func parseAssignment(line string) (string, string, error) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", "", errors.New("expected key = value")
	}
	key := strings.TrimSpace(parts[0])
	if key == "" {
		return "", "", errors.New("empty field name")
	}
	value := strings.TrimSpace(parts[1])
	return key, strings.Trim(value, "\""), nil
}
