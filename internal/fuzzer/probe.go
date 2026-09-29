package fuzzer

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	uuidToken     = "{uuid}"
	tempfileToken = "{tempfile}"
	markerPrefix  = "mcpwn_probe_"
)

type probeContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type probeResponse struct {
	Content []probeContent `json:"content"`
	IsError bool           `json:"isError"`
}

type probeRender struct {
	command string
	expect  string
	marker  string
	cleanup func()
}

func renderProbe(payload Payload) (probeRender, error) {
	token, err := randomToken()
	if err != nil {
		return probeRender{}, fmt.Errorf("probe token generation failed: %w", err)
	}
	marker := markerPrefix + token
	render := probeRender{marker: marker, cleanup: func() {}}

	command := strings.ReplaceAll(payload.Template, uuidToken, marker)
	expect := strings.ReplaceAll(payload.Expect, uuidToken, marker)

	if strings.Contains(command, tempfileToken) {
		path, cleanup, err := createTempProbeFile(marker)
		if err != nil {
			return probeRender{}, err
		}
		command = strings.ReplaceAll(command, tempfileToken, path)
		render.cleanup = cleanup
	}

	if err := isForbidden(command); err != nil {
		render.cleanup()
		return probeRender{}, fmt.Errorf("payload %s rendered unsafe: %w", payload.Name, err)
	}

	render.command = command
	render.expect = expect
	return render, nil
}

func createTempProbeFile(marker string) (string, func(), error) {
	file, err := os.CreateTemp("", "mcpwn_probe_*")
	if err != nil {
		return "", nil, fmt.Errorf("temp probe file creation failed: %w", err)
	}
	path := file.Name()
	if _, err := file.WriteString(marker); err != nil {
		file.Close()
		os.Remove(path)
		return "", nil, fmt.Errorf("temp probe file write failed: %w", err)
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return "", nil, fmt.Errorf("temp probe file close failed: %w", err)
	}
	return path, func() { os.Remove(path) }, nil
}

func randomToken() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random token generation failed: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func responseText(raw json.RawMessage) string {
	var resp probeResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return string(raw)
	}
	var builder strings.Builder
	for _, content := range resp.Content {
		if content.Type == "text" {
			builder.WriteString(content.Text)
		}
	}
	return builder.String()
}
