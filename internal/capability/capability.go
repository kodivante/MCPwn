package capability

import (
	"sort"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/schema"
)

const (
	Exec        = "exec"
	Filesystem  = "filesystem"
	Network     = "network"
	Database    = "database"
	State       = "state"
	Credentials = "credentials"
	Prompt      = "prompt"
	Resource    = "resource"
)

type ToolCapability struct {
	Tool         string   `json:"tool"`
	Capabilities []string `json:"capabilities"`
}

type marker struct {
	capability string
	keywords   []string
}

var paramMarkers = []marker{
	{capability: Exec, keywords: []string{"cmd", "command", "exec", "script", "shell", "bash"}},
	{capability: Filesystem, keywords: []string{"path", "file", "dir", "folder", "directory", "filename"}},
	{capability: Network, keywords: []string{"url", "endpoint", "webhook", "host", "port", "http"}},
	{capability: Database, keywords: []string{"sql", "query", "database", "table", "statement"}},
	{capability: State, keywords: []string{"delete", "remove", "update", "insert", "mutate", "state"}},
	{capability: Credentials, keywords: []string{"password", "token", "apikey", "secret", "credential", "auth"}},
	{capability: Resource, keywords: []string{"uri", "resource"}},
}

var descriptionMarkers = []marker{
	{capability: Exec, keywords: []string{"execute", "command", "shell", "run a", "script"}},
	{capability: Filesystem, keywords: []string{"file", "directory", "filesystem", "path"}},
	{capability: Network, keywords: []string{"http", "url", "web", "network", "fetch", "request"}},
	{capability: Database, keywords: []string{"database", "sql", "query", "table"}},
	{capability: State, keywords: []string{"delete", "update", "create", "modify", "mutate"}},
	{capability: Credentials, keywords: []string{"credential", "password", "token", "secret", "login", "auth"}},
	{capability: Resource, keywords: []string{"resource"}},
	{capability: Prompt, keywords: []string{"prompt"}},
}

func Profile(tools []schema.Tool) []ToolCapability {
	profiles := make([]ToolCapability, 0, len(tools))
	for _, tool := range tools {
		profiles = append(profiles, profileTool(tool))
	}
	return profiles
}

func profileTool(tool schema.Tool) ToolCapability {
	detected := make(map[string]bool)
	text := strings.ToLower(tool.Name + " " + tool.Description)
	for _, entry := range descriptionMarkers {
		if containsAny(text, entry.keywords) {
			detected[entry.capability] = true
		}
	}
	for key, prop := range tool.InputSchema.Properties {
		paramText := strings.ToLower(key + " " + prop.Description)
		for _, entry := range paramMarkers {
			if containsAny(paramText, entry.keywords) {
				detected[entry.capability] = true
			}
		}
	}
	capabilities := make([]string, 0, len(detected))
	for capability := range detected {
		capabilities = append(capabilities, capability)
	}
	sort.Strings(capabilities)
	return ToolCapability{Tool: tool.Name, Capabilities: capabilities}
}

func ServerCapabilities(profiles []ToolCapability) []string {
	present := make(map[string]bool)
	for _, profile := range profiles {
		for _, capability := range profile.Capabilities {
			present[capability] = true
		}
	}
	capabilities := make([]string, 0, len(present))
	for capability := range present {
		capabilities = append(capabilities, capability)
	}
	sort.Strings(capabilities)
	return capabilities
}

func ToolWithCapability(profiles []ToolCapability, capability string) (string, bool) {
	for _, profile := range profiles {
		for _, entry := range profile.Capabilities {
			if entry == capability {
				return profile.Tool, true
			}
		}
	}
	return "", false
}

func Contains(profile ToolCapability, capability string) bool {
	for _, entry := range profile.Capabilities {
		if entry == capability {
			return true
		}
	}
	return false
}

func containsAny(text string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(text, keyword) {
			return true
		}
	}
	return false
}
