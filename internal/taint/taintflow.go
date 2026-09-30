package taint

import "strings"

type analyzer struct {
	functions    map[string]*functionUnit
	visited      map[string]bool
	returnsTaint map[string]bool
	returnsType  map[string]string
	classes      map[string]bool
	classTaint   map[string]map[string]bool
	paths        []Path
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
	scope := newScope(unit)
	local := copyTaint(tainted)
	for attribute := range a.classTaint[owningClass(name)] {
		local["self."+attribute] = true
	}
	returns := false
	for index, line := range unit.body {
		a.applyGuards(unit.body, index, local)
		if lhs, rhs, ok := matchAssignment(line.text); ok {
			if a.handleSanitization(scope, rhs) {
				delete(local, lhs)
				continue
			}
			if a.handleConstructor(scope, rhs) {
				scope.types[lhs] = scope.resolveCallee(firstCallee(rhs), a)
				continue
			}
			if target, ok := a.handleCallableAlias(scope, rhs); ok {
				scope.aliases[lhs] = target
				continue
			}
			rhsTainted := containsTainted(rhs, local)
			if a.processCalls(scope, rhs, line.num, local, hops, entryTool, entryLabel, depth) {
				rhsTainted = true
			}
			if rhsTainted {
				local[lhs] = true
				if strings.HasPrefix(lhs, "self.") {
					a.recordClassTaint(owningClass(name), strings.TrimPrefix(lhs, "self."))
				}
			}
			continue
		}
		if expr, ok := matchReturn(line.text); ok {
			called := a.processCalls(scope, expr, line.num, local, hops, entryTool, entryLabel, depth)
			if containsTainted(expr, local) || carriesObjectTaint(expr, local) || called {
				returns = true
			}
			if returnType := a.returnedType(scope, name, expr); returnType != "" {
				a.returnsType[name] = returnType
			}
			continue
		}
		a.processCalls(scope, line.text, line.num, local, hops, entryTool, entryLabel, depth)
	}
	a.returnsTaint[key] = returns
}

func (a *analyzer) applyGuards(body []bodyLine, index int, local map[string]bool) {
	match := guardPattern.FindStringSubmatch(body[index].text)
	if match == nil {
		return
	}
	if !guardRejects(body, index) {
		return
	}
	delete(local, match[1])
}

func guardRejects(body []bodyLine, index int) bool {
	if strings.Contains(body[index].text, "return") || strings.Contains(body[index].text, "raise") {
		return true
	}
	for offset := 1; offset <= 2 && index+offset < len(body); offset++ {
		candidate := body[index+offset]
		if strings.TrimSpace(candidate.text) == "" {
			continue
		}
		if indentOf(candidate.text) <= indentOf(body[index].text) {
			return false
		}
		return raisePattern.MatchString(candidate.text)
	}
	return false
}

func (a *analyzer) handleSanitization(scope *scope, rhs string) bool {
	shape, pure := pureCleanser(rhs)
	if !pure {
		return false
	}
	return isCleanser(scope.resolveCallee(shape.callee, a))
}

func (a *analyzer) handleConstructor(scope *scope, rhs string) bool {
	calls := extractCalls(strings.TrimSpace(rhs), 0)
	if len(calls) == 0 {
		return false
	}
	return a.classes[calls[0].callee]
}

func (a *analyzer) handleCallableAlias(scope *scope, rhs string) (string, bool) {
	trimmed := strings.TrimSpace(rhs)
	if trimmed == "" || strings.ContainsAny(trimmed, "()=+-*/") {
		return "", false
	}
	if len(identifiers(trimmed)) != 1 {
		return "", false
	}
	resolved := scope.resolveCallee(trimmed, a)
	if a.classes[resolved] {
		return "", false
	}
	if a.functions[resolved] != nil {
		return resolved, true
	}
	if class, isSink := sinkClass(resolved); isSink && class != "" {
		return resolved, true
	}
	return "", false
}

func firstCallee(rhs string) string {
	calls := extractCalls(strings.TrimSpace(rhs), 0)
	if len(calls) == 0 {
		return ""
	}
	return calls[0].callee
}

func (a *analyzer) processCalls(scope *scope, text string, num int, local map[string]bool, hops []Hop, entryTool, entryLabel string, depth int) bool {
	returned := false
	chainedType := ""
	for _, call := range extractCalls(text, num) {
		resolved := scope.resolveReceiver(call.callee, call.receiver, chainedType, a)
		if class, isSink := sinkClass(resolved); isSink && argsTainted(call.args, local) {
			a.recordPath(entryTool, entryLabel, class, hops, resolved, call)
		}
		callee := a.functions[resolved]
		stateful := callee != nil && len(a.classTaint[owningClass(resolved)]) > 0
		if callee != nil && (argsTainted(call.args, local) || stateful) {
			childTaint := mapParams(callee.params, call.args, local)
			calleeKey := resolved + "|" + signature(childTaint)
			childHops := append(copyHops(hops), Hop{Function: resolved, File: callee.file, Line: num})
			a.process(resolved, childTaint, childHops, entryTool, entryLabel, depth+1)
			if a.returnsTaint[calleeKey] {
				returned = true
			}
		}
		chainedType = a.nextChainedType(resolved)
	}
	return returned
}

func owningClass(name string) string {
	if index := strings.Index(name, "."); index > 0 {
		return name[:index]
	}
	return ""
}

func (a *analyzer) recordClassTaint(class, attribute string) {
	if class == "" {
		return
	}
	if a.classTaint[class] == nil {
		a.classTaint[class] = make(map[string]bool)
	}
	a.classTaint[class][attribute] = true
}

func carriesObjectTaint(expr string, local map[string]bool) bool {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" || strings.ContainsAny(trimmed, " ()") {
		return false
	}
	prefix := trimmed + "."
	for key := range local {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func (a *analyzer) nextChainedType(resolved string) string {
	if a.classes[resolved] {
		return resolved
	}
	return a.returnsType[resolved]
}

func (a *analyzer) returnedType(scope *scope, name string, expr string) string {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "self" {
		if index := strings.Index(name, "."); index > 0 {
			return name[:index]
		}
		return ""
	}
	if match := constructorReceiverPattern.FindStringSubmatch(trimmed); match != nil && a.classes[match[1]] {
		return match[1]
	}
	return ""
}

func (a *analyzer) recordPath(entryTool, entryLabel, class string, hops []Hop, sinkName string, call callInfo) {
	if len(a.paths) >= maxPaths {
		return
	}
	sinkHop := Hop{Function: sinkName, File: hops[len(hops)-1].File, Line: call.line}
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
