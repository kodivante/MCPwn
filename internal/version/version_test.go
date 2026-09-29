package version

import (
	"strings"
	"testing"
)

func TestVersionFormat(t *testing.T) {
	parts := strings.Split(Version, ".")
	if len(parts) != 3 {
		t.Fatalf("expected semver with 3 parts, got %s", Version)
	}
	for _, part := range parts {
		if part == "" {
			t.Fatalf("expected numeric semver parts, got %s", Version)
		}
	}
}
