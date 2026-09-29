package fuzzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCommunityPacksParse(t *testing.T) {
	packs, err := filepath.Glob("../../packs/*.mcpwn")
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(packs) == 0 {
		t.Fatal("expected community packs in packs/ directory")
	}
	for _, pack := range packs {
		data, err := os.ReadFile(pack)
		if err != nil {
			t.Errorf("read %s failed: %v", pack, err)
			continue
		}
		if _, err := ParseDSL(data); err != nil {
			t.Errorf("parse %s failed: %v", pack, err)
		}
	}
}
