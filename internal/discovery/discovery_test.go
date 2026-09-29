package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, path, content string) string {
	t.Helper()
	full := filepath.Join(t.TempDir(), path)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatalf("dir creation failed: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0644); err != nil {
		t.Fatalf("config write failed: %v", err)
	}
	return full
}

func TestScanConfigParsesMcpServers(t *testing.T) {
	config := `{"mcpServers":{"filesystem":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]},"remote":{"url":"https://mcp.example.com/mcp"}}}`
	servers, err := scanConfig(writeConfig(t, "test/mcp.json", config))
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %+v", servers)
	}
	byRisk := map[string]string{}
	for _, server := range servers {
		byRisk[server.Name] = server.RiskClass
	}
	if byRisk["filesystem"] != "local-stdio" {
		t.Errorf("expected local-stdio, got %s", byRisk["filesystem"])
	}
	if byRisk["remote"] != "remote" {
		t.Errorf("expected remote, got %s", byRisk["remote"])
	}
}

func TestScanConfigClassifiesLocalHttp(t *testing.T) {
	config := `{"mcpServers":{"local":{"url":"http://127.0.0.1:8099/mcp"}}}`
	servers, err := scanConfig(writeConfig(t, "test/mcp2.json", config))
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if servers[0].RiskClass != "local-http" || servers[0].Transport != "http" {
		t.Errorf("unexpected classification: %+v", servers[0])
	}
}

func TestScanConfigIgnoresFilesWithoutMcpServers(t *testing.T) {
	path := writeConfig(t, "test/other.json", `{"something":"else"}`)
	if servers, err := scanConfig(path); err != nil || len(servers) != 0 {
		t.Errorf("expected no servers, got %+v err=%v", servers, err)
	}
}

func TestScanConfigMissingFile(t *testing.T) {
	if _, err := scanConfig(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("expected error for missing config")
	}
}

func TestDiscoverDeduplicatesByName(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	config := `{"mcpServers":{"dupe":{"command":"node","args":["server.js"]}}}`
	if err := os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(config), 0644); err != nil {
		t.Fatalf("config write failed: %v", err)
	}
	servers, err := Discover()
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}
	counts := map[string]int{}
	for _, server := range servers {
		counts[server.Name]++
	}
	if counts["dupe"] > 1 {
		t.Errorf("expected deduplicated entries, got %+v", servers)
	}
}

func TestPrintInventory(t *testing.T) {
	if output := PrintInventory(nil); output == "" {
		t.Error("expected non-empty inventory output")
	}
	output := PrintInventory([]DiscoveredServer{{Name: "x", RiskClass: "local-stdio", Command: "node", Source: "cfg"}})
	if len(output) == 0 || !strings.Contains(output, "local-stdio") {
		t.Errorf("expected formatted inventory with risk class, got %q", output)
	}
}
