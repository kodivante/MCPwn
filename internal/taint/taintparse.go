package taint

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maxFiles = 2000

type functionUnit struct {
	name     string
	file     string
	toolName string
	isTool   bool
	defLine  int
	params   []string
	body     []bodyLine
}

type bodyLine struct {
	text string
	num  int
}

type callInfo struct {
	callee string
	args   string
	line   int
}

var (
	defPattern    = regexp.MustCompile(`^\s*def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)`)
	jsFuncPattern = regexp.MustCompile(`^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)`)
	jsArrowNamed  = regexp.MustCompile(`^\s*(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>`)
	jsToolPattern = regexp.MustCompile(`\.tool\(\s*["']([^"']+)["']\s*,\s*([A-Za-z_$][\w$]*)`)
	assignPattern = regexp.MustCompile(`^\s*([A-Za-z_$][\w$]*)\s*=\s*(.+)$`)
	returnPattern = regexp.MustCompile(`^\s*return\s+(.+)$`)
)

func collectSourceFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || len(files) >= maxFiles {
			return walkErr
		}
		if entry.IsDir() {
			if isSkippedDir(entry.Name()) && path != root {
				return fs.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(entry.Name())) {
		case ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs":
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func isSkippedDir(name string) bool {
	switch name {
	case "node_modules", "venv", ".venv", "dist", "build", "vendor", "site-packages", ".git":
		return true
	default:
		return false
	}
}

func parseFile(path string) []*functionUnit {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if len(data) > 1024*1024 {
		return nil
	}
	rawLines := strings.Split(string(data), "\n")
	if strings.HasSuffix(strings.ToLower(path), ".py") {
		return parsePython(path, rawLines)
	}
	return parseJavaScript(path, rawLines)
}

func parsePython(path string, rawLines []string) []*functionUnit {
	var units []*functionUnit
	pendingTool := false
	for index, raw := range rawLines {
		lineNumber := index + 1
		if strings.HasPrefix(strings.TrimSpace(raw), "@") {
			pendingTool = pendingTool || strings.Contains(raw, ".tool")
			continue
		}
		match := defPattern.FindStringSubmatch(raw)
		if match == nil {
			continue
		}
		unit := &functionUnit{
			name:     match[1],
			file:     path,
			isTool:   pendingTool,
			toolName: match[1],
			defLine:  lineNumber,
			params:   splitParams(match[2]),
		}
		unit.body = pythonBody(rawLines, index, indentOf(raw))
		units = append(units, unit)
		pendingTool = false
	}
	return units
}

func pythonBody(rawLines []string, defIndex, defIndent int) []bodyLine {
	var body []bodyLine
	for index := defIndex + 1; index < len(rawLines); index++ {
		raw := rawLines[index]
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if indentOf(raw) <= defIndent {
			break
		}
		body = append(body, bodyLine{text: raw, num: index + 1})
	}
	return body
}

func parseJavaScript(path string, rawLines []string) []*functionUnit {
	var units []*functionUnit
	handlers := map[string]string{}
	for _, raw := range rawLines {
		if match := jsToolPattern.FindStringSubmatch(raw); match != nil {
			handlers[match[2]] = match[1]
		}
	}
	for index, raw := range rawLines {
		var match []string
		if match = jsFuncPattern.FindStringSubmatch(raw); match == nil {
			match = jsArrowNamed.FindStringSubmatch(raw)
		}
		if match == nil {
			continue
		}
		unit := &functionUnit{
			name:     match[1],
			file:     path,
			defLine:  index + 1,
			params:   splitParams(match[2]),
			toolName: handlers[match[1]],
			isTool:   handlers[match[1]] != "",
		}
		unit.body = jsBody(rawLines, index)
		units = append(units, unit)
	}
	return units
}

func jsBody(rawLines []string, funcIndex int) []bodyLine {
	var body []bodyLine
	depth := 0
	started := false
	for index := funcIndex; index < len(rawLines) && index <= funcIndex+200; index++ {
		raw := rawLines[index]
		depth += strings.Count(raw, "{") - strings.Count(raw, "}")
		if started && depth <= 0 {
			break
		}
		if strings.Contains(raw, "{") {
			started = true
		}
		if index > funcIndex {
			body = append(body, bodyLine{text: raw, num: index + 1})
		}
		if !started && strings.Contains(raw, ";") {
			break
		}
	}
	return body
}

func indentOf(line string) int {
	count := 0
	for _, char := range line {
		if char == ' ' {
			count++
			continue
		}
		if char == '\t' {
			count += 4
			continue
		}
		break
	}
	return count
}

func splitParams(raw string) []string {
	var params []string
	for _, piece := range strings.Split(raw, ",") {
		piece = strings.TrimSpace(piece)
		if piece == "" {
			continue
		}
		if cut := strings.IndexAny(piece, ":="); cut > 0 {
			piece = strings.TrimSpace(piece[:cut])
		}
		if piece == "self" || piece == "cls" {
			continue
		}
		params = append(params, piece)
	}
	return params
}

func matchAssignment(line string) (string, string, bool) {
	match := assignPattern.FindStringSubmatch(line)
	if match == nil || strings.HasPrefix(match[2], "=") {
		return "", "", false
	}
	return match[1], match[2], true
}

func matchReturn(line string) (string, bool) {
	match := returnPattern.FindStringSubmatch(line)
	if match == nil {
		return "", false
	}
	return match[1], true
}

func extractCalls(line string, lineNumber int) []callInfo {
	cleaned := stripStrings(line)
	var calls []callInfo
	for index := 0; index < len(cleaned); index++ {
		open := strings.Index(cleaned[index:], "(")
		if open < 0 {
			break
		}
		start := index + open
		nameStart := start - 1
		for nameStart >= 0 && isNameChar(cleaned[nameStart]) {
			nameStart--
		}
		callee := cleaned[nameStart+1 : start]
		end, ok := matchingParen(cleaned, start)
		index = start
		if !ok {
			continue
		}
		if callee != "" && callee != "if" && callee != "for" && callee != "while" {
			calls = append(calls, callInfo{callee: callee, args: cleaned[start+1 : end], line: lineNumber})
		}
		index = end
	}
	return calls
}

func matchingParen(text string, open int) (int, bool) {
	depth := 0
	for index := open; index < len(text); index++ {
		switch text[index] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return index, true
			}
		}
	}
	return 0, false
}

func isNameChar(char byte) bool {
	return char == '_' || char == '$' || char == '.' ||
		(char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')
}

func stripStrings(line string) string {
	var builder strings.Builder
	quote := byte(0)
	for index := 0; index < len(line); index++ {
		char := line[index]
		switch {
		case quote != 0:
			if char == quote && (index == 0 || line[index-1] != '\\') {
				quote = 0
				builder.WriteByte(' ')
			}
		case char == '"' || char == '\'':
			quote = char
		default:
			builder.WriteByte(char)
		}
	}
	return builder.String()
}

func identifiers(text string) []string {
	pattern := regexp.MustCompile(`[A-Za-z_$][\w$]*`)
	var found []string
	for _, name := range pattern.FindAllString(text, -1) {
		if isKeyword(name) {
			continue
		}
		found = append(found, name)
	}
	return found
}

func isKeyword(name string) bool {
	switch name {
	case "and", "or", "not", "in", "if", "else", "elif", "for", "while", "return",
		"None", "True", "False", "lambda", "await", "async", "new", "typeof", "yield", "with", "as", "is", "def", "class", "import", "from", "const", "let", "var", "function":
		return true
	default:
		return false
	}
}
