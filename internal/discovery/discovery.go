package discovery

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type DiscoveredServer struct {
	Name      string `json:"name"`
	Transport string `json:"transport"`
	Command   string `json:"command,omitempty"`
	URL       string `json:"url,omitempty"`
	Source    string `json:"source"`
	RiskClass string `json:"riskClass"`
}

type mcpServersFile struct {
	McpServers map[string]mcpServerEntry `json:"mcpServers"`
}

type mcpServerEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	URL     string   `json:"url"`
	Type    string   `json:"type"`
}

func Discover() ([]DiscoveredServer, error) {
	locations := defaultLocations()
	home, homeErr := os.UserHomeDir()
	if homeErr == nil {
		locations = append(locations, homeLocations(home)...)
	}
	var servers []DiscoveredServer
	seen := make(map[string]bool)
	for _, location := range locations {
		discovered, err := scanConfig(location)
		if err != nil {
			continue
		}
		for _, server := range discovered {
			key := server.Name + "|" + server.Transport + "|" + server.URL + "|" + server.Command
			if seen[key] {
				continue
			}
			seen[key] = true
			servers = append(servers, server)
		}
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].Name < servers[j].Name })
	return servers, nil
}

func defaultLocations() []string {
	return []string{
		".mcp.json",
		filepath.Join(".cursor", "mcp.json"),
		filepath.Join(".vscode", "mcp.json"),
	}
}

func homeLocations(home string) []string {
	locations := []string{
		filepath.Join(home, ".claude.json"),
		filepath.Join(home, ".mcp.json"),
		filepath.Join(home, ".cursor", "mcp.json"),
		filepath.Join(home, ".vscode", "mcp.json"),
	}
	if runtime.GOOS == "darwin" {
		locations = append(locations, filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"))
	} else if runtime.GOOS == "windows" {
		locations = append(locations, filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"))
	} else {
		locations = append(locations, filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"))
	}
	return locations
}

func scanConfig(path string) ([]DiscoveredServer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config read failed: %w", err)
	}
	var parsed mcpServersFile
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("config parsing failed: %w", err)
	}
	var servers []DiscoveredServer
	for name, entry := range parsed.McpServers {
		servers = append(servers, DiscoveredServer{
			Name:      name,
			Transport: transportOf(entry),
			Command:   strings.TrimSpace(entry.Command + " " + strings.Join(entry.Args, " ")),
			URL:       entry.URL,
			Source:    path,
			RiskClass: classify(entry),
		})
	}
	return servers, nil
}

func transportOf(entry mcpServerEntry) string {
	if entry.URL != "" || entry.Type == "http" || entry.Type == "sse" {
		if entry.Type == "sse" {
			return "sse"
		}
		return "http"
	}
	return "stdio"
}

func classify(entry mcpServerEntry) string {
	if entry.URL != "" {
		parsed, err := url.Parse(entry.URL)
		if err != nil {
			return "remote"
		}
		host := parsed.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
			return "local-http"
		}
		return "remote"
	}
	return "local-stdio"
}

func PrintInventory(servers []DiscoveredServer) string {
	var builder strings.Builder
	builder.WriteString("MCP servers discovered on this machine:\n")
	if len(servers) == 0 {
		builder.WriteString("  none found in known configuration locations\n")
		return builder.String()
	}
	for _, server := range servers {
		detail := server.Command
		if server.URL != "" {
			detail = server.URL
		}
		fmt.Fprintf(&builder, "  %-20s %-12s %-40s %s\n", server.Name, server.RiskClass, detail, server.Source)
	}
	return builder.String()
}
