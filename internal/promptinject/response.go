package promptinject

import (
	"encoding/json"
	"strings"
)

type probeContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type probeResponse struct {
	Content []probeContent `json:"content"`
	IsError bool           `json:"isError"`
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
