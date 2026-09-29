package supplychain

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

func writeManifest(t *testing.T, name, content string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0644); err != nil {
		t.Fatalf("manifest write failed: %v", err)
	}
	return root
}

func findingByRule(findings []auditor.Finding, ruleID string) []auditor.Finding {
	var matched []auditor.Finding
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			matched = append(matched, finding)
		}
	}
	return matched
}

func TestParseRequirements(t *testing.T) {
	root := writeManifest(t, "requirements.txt", "requests==2.31.0\nnumpy\n# comment\nflask>=2.0\n")
	dependencies, err := DiscoverDependencies(root)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}
	if len(dependencies) != 3 {
		t.Fatalf("expected 3 dependencies, got %+v", dependencies)
	}
	if dependencies[0].Name != "flask" || dependencies[0].Pinned {
		t.Errorf("flask must be unpinned: %+v", dependencies[0])
	}
	if dependencies[2].Name != "requests" || !dependencies[2].Pinned || dependencies[2].Version != "2.31.0" {
		t.Errorf("requests must be pinned to 2.31.0: %+v", dependencies[2])
	}
}

func TestParsePackageJSON(t *testing.T) {
	root := writeManifest(t, "package.json", `{"dependencies":{"express":"^4.18.0","lodash":"4.17.21"},"devDependencies":{"mocha":"10.0.0"}}`)
	dependencies, err := DiscoverDependencies(root)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}
	if len(dependencies) != 3 {
		t.Fatalf("expected 3 dependencies, got %+v", dependencies)
	}
	for _, dependency := range dependencies {
		if dependency.Name == "express" && dependency.Pinned {
			t.Error("express with caret range must not count as pinned")
		}
		if dependency.Name == "lodash" && !dependency.Pinned {
			t.Error("exact lodash version must count as pinned")
		}
	}
}

func TestTyposquatDetection(t *testing.T) {
	root := writeManifest(t, "requirements.txt", "reqeusts==2.0.0\nrequests==2.31.0\n")
	engine := NewEngine(Options{Endpoint: "http://127.0.0.1:1", Timeout: 100000000})
	findings, err := engine.Audit(root)
	if err != nil {
		t.Fatalf("audit failed: %v", err)
	}
	typosquats := findingByRule(findings, "Typosquat01")
	if len(typosquats) != 1 {
		t.Fatalf("expected 1 typosquat finding, got %+v", findings)
	}
	if typosquats[0].TargetTool != "reqeusts" {
		t.Errorf("expected reqeusts flagged, got %s", typosquats[0].TargetTool)
	}
}

func TestUnpinnedDetection(t *testing.T) {
	root := writeManifest(t, "requirements.txt", "flask>=2.0\nrequests==2.31.0\n")
	engine := NewEngine(Options{Endpoint: "http://127.0.0.1:1", Timeout: 100000000})
	findings, err := engine.Audit(root)
	if err != nil {
		t.Fatalf("audit failed: %v", err)
	}
	unpinned := findingByRule(findings, "UnpinnedDep01")
	if len(unpinned) != 1 || unpinned[0].TargetTool != "flask" {
		t.Fatalf("expected 1 unpinned flask finding, got %+v", findings)
	}
}

func TestOSVVulnerabilityLookup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var query osvQuery
		if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if query.Package.Name == "requests" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"vulns":[{"id":"GHSA-test-1234","summary":"fake vuln"}]}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"vulns":[]}`))
	}))
	defer server.Close()

	root := writeManifest(t, "requirements.txt", "requests==2.0.0\n")
	engine := NewEngine(Options{Endpoint: server.URL, Timeout: 5000000000})
	findings, err := engine.Audit(root)
	if err != nil {
		t.Fatalf("audit failed: %v", err)
	}
	vulns := findingByRule(findings, vulnRuleID)
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability finding, got %+v", findings)
	}
	if !vulns[0].Confirmed || vulns[0].Severity != auditor.SeverityHigh {
		t.Errorf("unexpected finding shape: %+v", vulns[0])
	}
	if findingByRule(findings, "Typosquat01") != nil {
		t.Error("requests is popular and must not be typosquatted")
	}
}

func TestOSVOfflineSkipsVulns(t *testing.T) {
	root := writeManifest(t, "requirements.txt", "requests==2.0.0\n")
	engine := NewEngine(Options{Endpoint: "http://127.0.0.1:1", Timeout: 100000000})
	findings, err := engine.Audit(root)
	if err != nil {
		t.Fatalf("audit failed: %v", err)
	}
	if findingByRule(findings, vulnRuleID) != nil {
		t.Error("expected no vulnerability findings when OSV is unreachable")
	}
}

func TestEditDistance(t *testing.T) {
	if editDistance("reqeusts", "requests") != 1 {
		t.Errorf("expected transposition distance 1, got %d", editDistance("reqeusts", "requests"))
	}
	if editDistance("ab", "ac") != 1 {
		t.Errorf("expected distance 1, got %d", editDistance("ab", "ac"))
	}
}

func TestDiscoverEmptyRoot(t *testing.T) {
	dependencies, err := DiscoverDependencies(t.TempDir())
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}
	if len(dependencies) != 0 {
		t.Errorf("expected no dependencies, got %+v", dependencies)
	}
}
