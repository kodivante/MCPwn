package fuzzer

import (
	"fmt"
	"strings"
)

var destructivePrefixes = []string{
	"rm", "del", "format", "dd", "mkfs", "shutdown", "reboot", "kill",
	"sudo", "chmod", "chown", "curl", "wget", "nc", "netcat", "ssh", "scp",
}

var forbiddenSequences = []string{
	">", "|", "&&", ";", "$(", "`", "\n", "\r",
	"/etc/passwd", "/etc/shadow", ".ssh", ".env",
}

func ValidatePayload(payload Payload) error {
	if err := isForbidden(payload.Template); err != nil {
		return fmt.Errorf("payload %s: %w", payload.Name, err)
	}
	return nil
}

func isForbidden(command string) error {
	lowered := strings.ToLower(command)
	for _, sequence := range forbiddenSequences {
		if strings.Contains(lowered, sequence) {
			return fmt.Errorf("forbidden sequence %q", sequence)
		}
	}
	for _, field := range strings.Fields(lowered) {
		for _, prefix := range destructivePrefixes {
			if strings.HasPrefix(field, prefix) {
				return fmt.Errorf("forbidden token %q", field)
			}
		}
	}
	return nil
}
