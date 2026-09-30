package taint

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kodivante/MCPwn/v3/internal/auditor"
)

const (
	ruleID       = "SourceTaint01"
	maxPaths     = 100
	maxCallDepth = 12
)

type Hop struct {
	Function string `json:"function"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

type Path struct {
	Tool      string   `json:"tool"`
	Entry     string   `json:"entry"`
	Params    []string `json:"params"`
	SinkClass string   `json:"sinkClass"`
	Hops      []Hop    `json:"hops"`
}

func (p Path) Evidence() string {
	labels := make([]string, 0, len(p.Hops))
	for _, hop := range p.Hops {
		labels = append(labels, fmt.Sprintf("%s (%s:%d)", hop.Function, hop.File, hop.Line))
	}
	return strings.Join(labels, " -> ")
}

type analyzer struct {
	functions    map[string]*functionUnit
	visited      map[string]bool
	returnsTaint map[string]bool
	paths        []Path
}

func Analyze(root string) ([]auditor.Finding, []Path, error) {
	files, err := collectSourceFiles(root)
	if err != nil {
		return nil, nil, fmt.Errorf("taint source walk failed: %w", err)
	}
	engine := &analyzer{
		functions:    make(map[string]*functionUnit),
		visited:      make(map[string]bool),
		returnsTaint: make(map[string]bool),
	}
	for _, file := range files {
		for _, unit := range parseFile(file) {
			if _, exists := engine.functions[unit.name]; !exists {
				engine.functions[unit.name] = unit
			}
		}
	}
	for _, name := range sortedFunctionNames(engine.functions) {
		unit := engine.functions[name]
		if !unit.isTool {
			continue
		}
		entry := Hop{Function: name, File: unit.file, Line: unit.defLine}
		engine.process(name, allParamsTainted(unit), []Hop{entry}, unit.toolName, unit.toolName+"("+strings.Join(unit.params, ", ")+")", 0)
	}
	return findingsFromPaths(engine.paths), engine.paths, nil
}

func (a *analyzer) process(name string, tainted map[string]bool, hops []Hop, entryTool, entryLabel string, depth int) {
	key := name + "|" + signature(tainted)
	if a.visited[key] || depth > maxCallDepth {
		return
	}
	a.visited[key] = true
	unit := a.functions[name]
	if unit == nil {
		return
	}
	local := copyTaint(tainted)
	returns := false
	for _, line := range unit.body {
		if lhs, rhs, ok := matchAssignment(line.text); ok {
			rhsTainted := containsTainted(rhs, local)
			if a.processCalls(rhs, line.num, local, hops, entryTool, entryLabel, depth) {
				rhsTainted = true
			}
			if rhsTainted {
				local[lhs] = true
			}
			continue
		}
		if expr, ok := matchReturn(line.text); ok {
			called := a.processCalls(expr, line.num, local, hops, entryTool, entryLabel, depth)
			if containsTainted(expr, local) || called {
				returns = true
			}
			continue
		}
		a.processCalls(line.text, line.num, local, hops, entryTool, entryLabel, depth)
	}
	a.returnsTaint[key] = returns
}

func (a *analyzer) processCalls(text string, num int, local map[string]bool, hops []Hop, entryTool, entryLabel string, depth int) bool {
	returned := false
	for _, call := range extractCalls(text, num) {
		if class, isSink := sinkClass(call.callee); isSink && argsTainted(call.args, local) {
			a.recordPath(entryTool, entryLabel, class, hops, call)
		}
		callee := a.functions[call.callee]
		if callee == nil || !argsTainted(call.args, local) {
			continue
		}
		childTaint := mapParams(callee.params, call.args, local)
		calleeKey := call.callee + "|" + signature(childTaint)
		childHops := append(copyHops(hops), Hop{Function: call.callee, File: callee.file, Line: num})
		a.process(call.callee, childTaint, childHops, entryTool, entryLabel, depth+1)
		if a.returnsTaint[calleeKey] {
			returned = true
		}
	}
	return returned
}

func (a *analyzer) recordPath(entryTool, entryLabel, class string, hops []Hop, call callInfo) {
	if len(a.paths) >= maxPaths {
		return
	}
	sinkHop := Hop{Function: call.callee, File: hops[len(hops)-1].File, Line: call.line}
	recorded := Path{
		Tool:      entryTool,
		Entry:     entryLabel,
		SinkClass: class,
		Hops:      append(copyHops(hops), sinkHop),
	}
	if entry := a.functions[entryTool]; entry != nil {
		recorded.Params = entry.params
	}
	a.paths = append(a.paths, recorded)
}

func findingsFromPaths(paths []Path) []auditor.Finding {
	seen := make(map[string]bool)
	var findings []auditor.Finding
	for _, path := range paths {
		key := path.Tool + "|" + path.SinkClass
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, auditor.Finding{
			Severity:    auditor.SeverityHigh,
			RuleID:      ruleID,
			TargetTool:  path.Tool,
			ParamPath:   "taint:" + path.SinkClass,
			Description: fmt.Sprintf("MCP tool input reaches a %s sink through %d interprocedural hops", path.SinkClass, len(path.Hops)-1),
			Remediation: remediationFor(path.SinkClass),
			Confirmed:   false,
			Evidence:    path.Evidence(),
		})
	}
	return findings
}

func remediationFor(class string) string {
	switch class {
	case "exec":
		return "Never pass tool input to a shell: use argument arrays, parameterized APIs or strict allowlists; trace the reported path and break it at the first hop."
	case "network":
		return "Validate URLs against an allowlist of hosts before any request; SSRF from tool input reaches internal services."
	case "filesystem":
		return "Normalize paths and confine access to an allowlisted root; tool input must never select arbitrary files."
	case "deserialization":
		return "Replace native deserializers with schema-validated JSON; tainted deserialization is remote code execution."
	default:
		return "Validate tool input before it reaches the reported sink and break the tainted path."
	}
}

func allParamsTainted(unit *functionUnit) map[string]bool {
	tainted := make(map[string]bool)
	for _, param := range unit.params {
		tainted[param] = true
	}
	return tainted
}

func mapParams(params []string, args string, local map[string]bool) map[string]bool {
	tainted := make(map[string]bool)
	chunks := strings.Split(args, ",")
	for index, chunk := range chunks {
		if index >= len(params) {
			break
		}
		if containsTainted(chunk, local) {
			tainted[params[index]] = true
		}
	}
	return tainted
}

func argsTainted(args string, local map[string]bool) bool {
	return containsTainted(args, local)
}

func containsTainted(text string, local map[string]bool) bool {
	for _, name := range identifiers(text) {
		if local[name] {
			return true
		}
	}
	return false
}

func copyTaint(source map[string]bool) map[string]bool {
	copied := make(map[string]bool, len(source))
	for key := range source {
		copied[key] = true
	}
	return copied
}

func copyHops(source []Hop) []Hop {
	copied := make([]Hop, len(source))
	copy(copied, source)
	return copied
}

func signature(tainted map[string]bool) string {
	names := make([]string, 0, len(tainted))
	for name := range tainted {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func sortedFunctionNames(functions map[string]*functionUnit) []string {
	names := make([]string, 0, len(functions))
	for name := range functions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
