package supplychain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

const (
	defaultOSVEndpoint = "https://api.osv.dev"
	defaultTimeout     = 15 * time.Second
)

type Options struct {
	Endpoint string
	Timeout  time.Duration
}

type Engine struct {
	options Options
	client  *http.Client
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

func NewEngine(options Options) *Engine {
	if options.Endpoint == "" {
		options.Endpoint = defaultOSVEndpoint
	}
	if options.Timeout <= 0 {
		options.Timeout = defaultTimeout
	}
	return &Engine{options: options, client: &http.Client{Timeout: options.Timeout}}
}

func (e *Engine) Audit(root string) ([]auditor.Finding, error) {
	dependencies, err := DiscoverDependencies(root)
	if err != nil {
		return nil, err
	}
	var findings []auditor.Finding
	findings = append(findings, typosquatFindings(dependencies)...)
	findings = append(findings, unpinnedFindings(dependencies)...)
	findings = append(findings, e.vulnFindings(dependencies)...)
	return findings, nil
}

func (e *Engine) vulnFindings(dependencies []Dependency) []auditor.Finding {
	var findings []auditor.Finding
	for _, dependency := range dependencies {
		if dependency.Version == "" {
			continue
		}
		vulns, err := e.queryOSV(dependency)
		if err != nil || len(vulns) == 0 {
			continue
		}
		findings = append(findings, vulnFinding(dependency, vulns))
	}
	return findings
}

func (e *Engine) queryOSV(dependency Dependency) ([]osvVuln, error) {
	body, err := json.Marshal(osvQuery{
		Package: osvPackage{Name: dependency.Name, Ecosystem: dependency.Ecosystem},
		Version: dependency.Version,
	})
	if err != nil {
		return nil, fmt.Errorf("osv query serialization failed: %w", err)
	}
	resp, err := e.client.Post(e.options.Endpoint+"/v1/query", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv query failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv query returned status %d", resp.StatusCode)
	}
	var parsed osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("osv response parsing failed: %w", err)
	}
	return parsed.Vulns, nil
}

func vulnFinding(dependency Dependency, vulns []osvVuln) auditor.Finding {
	ids := make([]string, 0, len(vulns))
	for _, vuln := range vulns {
		ids = append(ids, vuln.ID)
	}
	if len(ids) > maxVulnsPerDep {
		ids = ids[:maxVulnsPerDep]
	}
	return auditor.Finding{
		Severity:    auditor.SeverityHigh,
		RuleID:      vulnRuleID,
		TargetTool:  dependency.Name,
		ParamPath:   "dependency",
		Description: fmt.Sprintf("Dependency %s@%s has %d known vulnerabilities", dependency.Name, dependency.Version, len(vulns)),
		Remediation: "Upgrade the dependency to a patched version; if a fix is unavailable, isolate the server and add compensating controls.",
		Confirmed:   true,
		Evidence:    fmt.Sprintf("osv.dev reports %s for %s@%s (%s ecosystem)", strings.Join(ids, ", "), dependency.Name, dependency.Version, dependency.Ecosystem),
	}
}

func typosquatFindings(dependencies []Dependency) []auditor.Finding {
	var findings []auditor.Finding
	for _, dependency := range dependencies {
		closest := closestPopular(dependency.Name)
		if closest == "" || isPopular(dependency.Name) {
			continue
		}
		findings = append(findings, auditor.Finding{
			Severity:    auditor.SeverityMedium,
			RuleID:      typosquatRuleID,
			TargetTool:  dependency.Name,
			ParamPath:   "dependency",
			Description: fmt.Sprintf("Dependency %s is one edit away from the popular package %s", dependency.Name, closest),
			Remediation: "Verify the package name against the official registry before installing; typosquats are a common supply-chain attack vector.",
			Evidence:    fmt.Sprintf("edit distance 1 from %q in the %s ecosystem", closest, dependency.Ecosystem),
		})
	}
	return findings
}

func unpinnedFindings(dependencies []Dependency) []auditor.Finding {
	var findings []auditor.Finding
	for _, dependency := range dependencies {
		if dependency.Pinned || dependency.Ecosystem != "PyPI" {
			continue
		}
		findings = append(findings, auditor.Finding{
			Severity:    auditor.SeverityLow,
			RuleID:      unpinnedRuleID,
			TargetTool:  dependency.Name,
			ParamPath:   "dependency",
			Description: fmt.Sprintf("Dependency %s is not pinned to an exact version", dependency.Name),
			Remediation: "Pin every dependency to an exact version (==) and validate hashes so builds are reproducible.",
			Evidence:    fmt.Sprintf("requirements entry %q lacks an == version constraint", dependency.Name),
		})
	}
	return findings
}
