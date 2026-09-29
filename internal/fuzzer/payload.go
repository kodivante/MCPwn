package fuzzer

import (
	"strings"
	"time"
)

type Payload struct {
	Name        string
	RuleID      string
	Template    string
	Expect      string
	MinDelay    time.Duration
	Description string
}

func BuiltinPayloads() []Payload {
	return []Payload{
		{
			Name:        "echoMarker",
			RuleID:      "CmdInjection01",
			Template:    "echo {uuid}",
			Expect:      "{uuid}",
			Description: "Confirms command execution using a benign echo with a unique marker",
		},
		{
			Name:        "sleepTiming",
			RuleID:      "CmdInjection01",
			Template:    "sleep 2",
			MinDelay:    2 * time.Second,
			Description: "Confirms command execution via a controlled two second delay",
		},
		{
			Name:        "tempFileRead",
			RuleID:      "CmdInjection01",
			Template:    "cat {tempfile}",
			Expect:      "{uuid}",
			Description: "Confirms command execution reading a fuzzer-created temp file",
		},
	}
}

func argumentKey(paramPath string) string {
	parts := strings.Split(paramPath, "[")
	if len(parts) < 2 {
		return ""
	}
	last := strings.TrimSuffix(parts[len(parts)-1], ".items")
	return strings.TrimRight(last, "]")
}
