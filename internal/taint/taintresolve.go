package taint

import (
	"regexp"
	"strings"
)

var (
	pyImportPattern  = regexp.MustCompile(`^\s*import\s+([A-Za-z_][\w.]*)(?:\s+as\s+([A-Za-z_]\w*))?`)
	pyFromPattern    = regexp.MustCompile(`^\s*from\s+([A-Za-z_][\w.]*)\s+import\s+([A-Za-z_][\w.*,\s]+)`)
	pyClassPattern   = regexp.MustCompile(`^\s*class\s+([A-Za-z_]\w*)`)
	jsRequirePattern = regexp.MustCompile(`^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"][^'"]*?([\w.-]+)['"]\s*\)`)
	jsImportPattern  = regexp.MustCompile(`^\s*import\s+([A-Za-z_$][\w$]*)\s+from\s+['"][^'"]*?([\w.-]+)['"]`)
	guardPattern     = regexp.MustCompile(`^\s*if\s+([A-Za-z_$][\w$.]*)\s+not\s+in\s+[A-Za-z_$][\w$.]*`)
	raisePattern     = regexp.MustCompile(`^\s*(return|raise)\b`)
)

type fileContext struct {
	imports map[string]string
	classes map[string]bool
}

func parseFileContext(rawLines []string, isPython bool) *fileContext {
	context := &fileContext{imports: make(map[string]string), classes: make(map[string]bool)}
	for _, raw := range rawLines {
		if match := pyClassPattern.FindStringSubmatch(raw); match != nil && isPython {
			context.classes[match[1]] = true
			continue
		}
		if match := pyImportPattern.FindStringSubmatch(raw); match != nil && isPython {
			canonical := match[1]
			alias := canonical
			if match[2] != "" {
				alias = match[2]
			}
			context.imports[alias] = canonical
			continue
		}
		if match := pyFromPattern.FindStringSubmatch(raw); match != nil && isPython {
			for _, piece := range strings.Split(match[2], ",") {
				entry := strings.TrimSpace(piece)
				if entry == "" {
					continue
				}
				segments := strings.Fields(entry)
				name := strings.Trim(segments[0], "(),")
				alias := name
				if len(segments) >= 3 && segments[1] == "as" {
					alias = segments[2]
				}
				context.imports[alias] = match[1] + "." + name
			}
			continue
		}
		if !isPython {
			if match := jsRequirePattern.FindStringSubmatch(raw); match != nil {
				context.imports[match[1]] = match[2]
				continue
			}
			if match := jsImportPattern.FindStringSubmatch(raw); match != nil {
				context.imports[match[1]] = match[2]
			}
		}
	}
	return context
}

type scope struct {
	unit    *functionUnit
	types   map[string]string
	aliases map[string]string
}

func newScope(unit *functionUnit) *scope {
	return &scope{unit: unit, types: make(map[string]string), aliases: make(map[string]string)}
}

var constructorReceiverPattern = regexp.MustCompile(`^([A-Za-z_$][\w$]*)\(\)$`)

func (s *scope) resolveCallee(callee string, analyzer *analyzer) string {
	return s.resolveReceiver(callee, "", "", analyzer)
}

func (s *scope) resolveReceiver(callee, receiver, chainedType string, analyzer *analyzer) string {
	base := strings.TrimLeft(callee, ".")
	resolved := base
	if chainedType != "" {
		resolved = chainedType + "." + base
		return resolved
	}
	if match := constructorReceiverPattern.FindStringSubmatch(receiver); match != nil && analyzer.classes[match[1]] {
		resolved = match[1] + "." + base
		return resolved
	}
	parts := strings.Split(base, ".")
	if len(parts) > 1 {
		if canonical, ok := s.unit.imports[parts[0]]; ok {
			resolved = canonical + "." + strings.Join(parts[1:], ".")
		} else if className, ok := s.types[parts[0]]; ok {
			resolved = className + "." + strings.Join(parts[1:], ".")
		}
	}
	if target, ok := s.aliases[resolved]; ok {
		return target
	}
	if target, ok := s.aliases[base]; ok {
		return target
	}
	if len(parts) == 1 && !analyzer.classes[base] {
		if canonical, ok := s.unit.imports[base]; ok {
			return canonical
		}
	}
	return resolved
}

var cleansers = map[string]bool{
	"shlex.quote":        true,
	"re.escape":          true,
	"int":                true,
	"float":              true,
	"bool":               true,
	"os.path.basename":   true,
	"html.escape":        true,
	"urllib.parse.quote": true,
}

func isCleanser(resolvedCallee string) bool {
	parts := strings.Split(resolvedCallee, ".")
	for index := range parts {
		candidate := strings.Join(parts[index:], ".")
		if cleansers[candidate] {
			return true
		}
	}
	return false
}

func pureCleanser(rhs string) (callInfo, bool) {
	trimmed := strings.TrimSpace(rhs)
	open := strings.Index(trimmed, "(")
	if open <= 0 {
		return callInfo{}, false
	}
	calls := extractCalls(trimmed, 0)
	if len(calls) == 0 {
		return callInfo{}, false
	}
	if calls[0].callee != trimmed[:open] {
		return callInfo{}, false
	}
	if strings.TrimSpace(trimmed[firstClosingIndex(trimmed):]) != ")" {
		return callInfo{}, false
	}
	return calls[0], true
}

func firstClosingIndex(text string) int {
	depth := 0
	for index := 0; index < len(text); index++ {
		switch text[index] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return len(text)
}
