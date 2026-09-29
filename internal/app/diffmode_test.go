package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

func TestDiffFindings(t *testing.T) {
	findingA := auditor.Finding{RuleID: "CmdInjection01", TargetTool: "tool", ParamPath: "p1"}
	findingB := auditor.Finding{RuleID: "PathTraversal01", TargetTool: "tool", ParamPath: "p2"}
	findingC := auditor.Finding{RuleID: "Dos01", TargetTool: "tool", ParamPath: "p3"}
	tests := []struct {
		name          string
		current       []auditor.Finding
		baseline      []auditor.Finding
		wantAdded     int
		wantFixed     int
		wantUnchanged int
	}{
		{
			name:          "identical",
			current:       []auditor.Finding{findingA},
			baseline:      []auditor.Finding{findingA},
			wantUnchanged: 1,
		},
		{
			name:      "all new",
			current:   []auditor.Finding{findingA, findingB},
			wantAdded: 2,
		},
		{
			name:      "all fixed",
			baseline:  []auditor.Finding{findingA, findingB},
			wantFixed: 2,
		},
		{
			name:          "mixed",
			current:       []auditor.Finding{findingA, findingB},
			baseline:      []auditor.Finding{findingA, findingC},
			wantAdded:     1,
			wantFixed:     1,
			wantUnchanged: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := diffFindings(tc.current, tc.baseline)
			if len(result.added) != tc.wantAdded {
				t.Errorf("expected %d added, got %d", tc.wantAdded, len(result.added))
			}
			if len(result.fixed) != tc.wantFixed {
				t.Errorf("expected %d fixed, got %d", tc.wantFixed, len(result.fixed))
			}
			if len(result.unchanged) != tc.wantUnchanged {
				t.Errorf("expected %d unchanged, got %d", tc.wantUnchanged, len(result.unchanged))
			}
		})
	}
}

func TestLoadBaselineFindings(t *testing.T) {
	baseline := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(baseline, []byte(`[{"RuleID":"Test01"}]`), 0644); err != nil {
		t.Fatal(err)
	}
	findings, err := loadBaselineFindings(baseline)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 baseline finding, got %d", len(findings))
	}
}

func TestLoadBaselineFindingsErrors(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{
			name:  "missing file",
			setup: func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing.json") },
		},
		{
			name: "invalid json",
			setup: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "bad.json")
				if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := loadBaselineFindings(tc.setup(t)); err == nil {
				t.Error("expected baseline load error")
			}
		})
	}
}

func TestRunDiff(t *testing.T) {
	baseline := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(baseline, []byte(`[]`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := runDiff([]auditor.Finding{{RuleID: "Test01"}}, baseline); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := runDiff(nil, filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("expected diff error for missing baseline")
	}
}
