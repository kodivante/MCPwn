package fuzzer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const payloadFileExtension = ".mcpwn"

type LoadResult struct {
	Payloads []Payload
	Warnings []string
}

func LoadPayloadFiles(paths ...string) (LoadResult, error) {
	result := LoadResult{Payloads: []Payload{}, Warnings: []string{}}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return result, fmt.Errorf("payload path %s unavailable: %w", path, err)
		}
		if info.IsDir() {
			if err := loadPayloadDirectory(path, &result); err != nil {
				return result, err
			}
			continue
		}
		if !strings.HasSuffix(path, payloadFileExtension) {
			result.Warnings = append(result.Warnings, fmt.Sprintf("skipping %s: %s extension required", path, payloadFileExtension))
			continue
		}
		if err := loadPayloadFile(path, &result); err != nil {
			return result, err
		}
	}
	return result, nil
}

func loadPayloadDirectory(path string, result *LoadResult) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("payload directory %s unreadable: %w", path, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), payloadFileExtension) {
			continue
		}
		if err := loadPayloadFile(filepath.Join(path, entry.Name()), result); err != nil {
			return err
		}
	}
	return nil
}

func loadPayloadFile(path string, result *LoadResult) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("payload file %s unreadable: %w", path, err)
	}
	payloads, err := ParseDSL(data)
	if err != nil {
		return fmt.Errorf("payload file %s: %w", path, err)
	}
	for _, payload := range payloads {
		if err := ValidatePayload(payload); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("payload %q in %s rejected: %v", payload.Name, path, err))
			continue
		}
		result.Payloads = append(result.Payloads, payload)
	}
	return nil
}
