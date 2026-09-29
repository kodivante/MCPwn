package supplychain

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	vulnRuleID      = "DependencyVuln01"
	typosquatRuleID = "Typosquat01"
	unpinnedRuleID  = "UnpinnedDep01"
	maxVulnsPerDep  = 5
)

type Dependency struct {
	Name      string
	Version   string
	Ecosystem string
	Pinned    bool
}

type manifestParser func(path string) ([]Dependency, error)

type manifestKind struct {
	filename  string
	ecosystem string
	parser    manifestParser
}

var manifests = []manifestKind{
	{filename: "requirements.txt", ecosystem: "PyPI", parser: parseRequirements},
	{filename: "package.json", ecosystem: "npm", parser: parsePackageJSON},
	{filename: "go.mod", ecosystem: "Go", parser: parseGoMod},
}

func DiscoverDependencies(root string) ([]Dependency, error) {
	var dependencies []Dependency
	for _, manifest := range manifests {
		path := filepath.Join(root, manifest.filename)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		found, err := manifest.parser(path)
		if err != nil {
			return nil, fmt.Errorf("%s parsing failed: %w", manifest.filename, err)
		}
		dependencies = append(dependencies, found...)
	}
	sort.Slice(dependencies, func(i, j int) bool {
		if dependencies[i].Ecosystem == dependencies[j].Ecosystem {
			return dependencies[i].Name < dependencies[j].Name
		}
		return dependencies[i].Ecosystem < dependencies[j].Ecosystem
	})
	return dependencies, nil
}

func parseRequirements(path string) ([]Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("requirements open failed: %w", err)
	}
	defer file.Close()
	var dependencies []Dependency
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		name, version, pinned := splitPipRequirement(line)
		dependencies = append(dependencies, Dependency{Name: name, Version: version, Ecosystem: "PyPI", Pinned: pinned})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("requirements read failed: %w", err)
	}
	return dependencies, nil
}

func splitPipRequirement(line string) (string, string, bool) {
	for _, separator := range []string{"==", ">=", "<=", "~=", "!=", ">", "<"} {
		if index := strings.Index(line, separator); index > 0 {
			return line[:index], strings.TrimSpace(line[index+len(separator):]), separator == "=="
		}
	}
	return line, "", false
}

func parsePackageJSON(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("package.json read failed: %w", err)
	}
	var parsed struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("package.json parsing failed: %w", err)
	}
	dependencies := make([]Dependency, 0, len(parsed.Dependencies)+len(parsed.DevDependencies))
	for section, entries := range map[string]map[string]string{"dependencies": parsed.Dependencies, "devDependencies": parsed.DevDependencies} {
		for name, version := range entries {
			dependencies = append(dependencies, Dependency{
				Name:      name,
				Version:   strings.TrimPrefix(strings.TrimPrefix(version, "^"), "~"),
				Ecosystem: "npm",
				Pinned:    section == "dependencies" && !strings.HasPrefix(version, "^") && !strings.HasPrefix(version, "~") && !strings.HasPrefix(version, "*"),
			})
		}
	}
	return dependencies, nil
}

func parseGoMod(path string) ([]Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("go.mod open failed: %w", err)
	}
	defer file.Close()
	var dependencies []Dependency
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || fields[0] != "require" || strings.HasPrefix(fields[1], "github.com/kodivante") {
			continue
		}
		dependencies = append(dependencies, Dependency{Name: fields[1], Version: strings.TrimPrefix(fields[2], "v"), Ecosystem: "Go", Pinned: true})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("go.mod read failed: %w", err)
	}
	return dependencies, nil
}
