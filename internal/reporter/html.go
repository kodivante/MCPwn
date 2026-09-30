package reporter

import (
	"bytes"
	"fmt"
	"html/template"
	"time"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
	"github.com/kodivante/MCPwn/v3/internal/owasp"
	"github.com/kodivante/MCPwn/v3/internal/risk"
	"github.com/kodivante/MCPwn/v3/internal/version"
)

var severityOrder = []auditor.Severity{auditor.SeverityCritical, auditor.SeverityHigh, auditor.SeverityMedium, auditor.SeverityLow}

type htmlFinding struct {
	SevClass     string
	RuleID       string
	TargetTool   string
	ParamPath    string
	Description  string
	Remediation  string
	StatusLabel  string
	StatusClass  string
	Evidence     string
	OwaspMcp     string
	Verification string
}

type owaspRow struct {
	ID          string
	Title       string
	Status      string
	Findings    int
	HasFindings bool
}

type htmlSection struct {
	Severity string
	Class    string
	Findings []htmlFinding
}

type htmlReport struct {
	Version       string
	GeneratedAt   string
	Total         int
	Confirmed     int
	RiskIndex     int
	RiskGrade     string
	CountCritical int
	CountHigh     int
	CountMedium   int
	CountLow      int
	Sections      []htmlSection
	Owasp         []owaspRow
}

func GenerateHTML(findings []auditor.Finding) ([]byte, error) {
	tmpl, err := template.New("mcpwn").Parse(htmlTemplate)
	if err != nil {
		return nil, fmt.Errorf("html template parsing failed: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, buildHTMLReport(findings)); err != nil {
		return nil, fmt.Errorf("html report rendering failed: %w", err)
	}
	return buf.Bytes(), nil
}

func buildHTMLReport(findings []auditor.Finding) htmlReport {
	sections := make([]htmlSection, 0, len(severityOrder))
	confirmed := 0
	for _, severity := range severityOrder {
		section, sectionConfirmed := buildHTMLSection(findings, severity)
		confirmed += sectionConfirmed
		if len(section.Findings) > 0 {
			sections = append(sections, section)
		}
	}
	report := htmlReport{
		Version:     version.Version,
		GeneratedAt: time.Now().Format(time.RFC3339),
		Total:       len(findings),
		Confirmed:   confirmed,
		Sections:    sections,
		Owasp:       buildOwaspRows(findings),
	}
	riskIndex := risk.ServerIndex(findings)
	report.RiskIndex = riskIndex.Index
	report.RiskGrade = riskIndex.Grade
	report.CountCritical = sectionCount(sections, auditor.SeverityCritical)
	report.CountHigh = sectionCount(sections, auditor.SeverityHigh)
	report.CountMedium = sectionCount(sections, auditor.SeverityMedium)
	report.CountLow = sectionCount(sections, auditor.SeverityLow)
	return report
}

func buildHTMLSection(findings []auditor.Finding, severity auditor.Severity) (htmlSection, int) {
	section := htmlSection{Severity: string(severity), Class: severityClass(severity), Findings: []htmlFinding{}}
	confirmed := 0
	for _, f := range findings {
		if f.Severity != severity {
			continue
		}
		if f.Confirmed {
			confirmed++
		}
		section.Findings = append(section.Findings, newHTMLFinding(f))
	}
	return section, confirmed
}

func newHTMLFinding(f auditor.Finding) htmlFinding {
	statusLabel := "[?] DETECTED"
	statusClass := "detected"
	if f.Confirmed {
		statusLabel = "[!] CONFIRMED"
		statusClass = "confirmed"
	}
	return htmlFinding{
		SevClass:     severityClass(f.Severity),
		RuleID:       f.RuleID,
		TargetTool:   f.TargetTool,
		ParamPath:    f.ParamPath,
		Description:  f.Description,
		Remediation:  f.Remediation,
		StatusLabel:  statusLabel,
		StatusClass:  statusClass,
		Evidence:     f.Evidence,
		OwaspMcp:     owasp.MapRule(f.RuleID),
		Verification: f.Verification,
	}
}

func buildOwaspRows(findings []auditor.Finding) []owaspRow {
	coverage := owasp.CoverageSummary(findings)
	rows := make([]owaspRow, 0, len(coverage))
	for _, item := range coverage {
		rows = append(rows, owaspRow{
			ID:          item.ID,
			Title:       item.Title,
			Status:      item.Status,
			Findings:    item.Findings,
			HasFindings: item.Findings > 0,
		})
	}
	return rows
}

func severityClass(severity auditor.Severity) string {
	switch severity {
	case auditor.SeverityCritical:
		return "critical"
	case auditor.SeverityHigh:
		return "high"
	case auditor.SeverityMedium:
		return "medium"
	default:
		return "low"
	}
}

func sectionCount(sections []htmlSection, severity auditor.Severity) int {
	for _, section := range sections {
		if section.Severity == string(severity) {
			return len(section.Findings)
		}
	}
	return 0
}
