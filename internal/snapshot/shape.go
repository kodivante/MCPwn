package snapshot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/kodivante/MCPwn/v3/internal/schema"
)

const (
	ctxArray = iota
	ctxObjectKey
	ctxObjectValue
)

func shapeKeys(raw json.RawMessage) []string {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var keys []string
	stack := []int{}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				stack = append(stack, ctxObjectKey)
			case '[':
				stack = append(stack, ctxArray)
			default:
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1] == ctxObjectKey {
				keys = append(keys, fmt.Sprintf("%d:%s", len(stack), value))
				stack[len(stack)-1] = ctxObjectValue
			} else if len(stack) > 0 && stack[len(stack)-1] == ctxObjectValue {
				stack[len(stack)-1] = ctxObjectKey
			}
		default:
			if len(stack) > 0 && stack[len(stack)-1] == ctxObjectValue {
				stack[len(stack)-1] = ctxObjectKey
			}
		}
	}
	return keys
}

func CollectShapes(caller ToolCaller, tools []schema.Tool) map[string]string {
	shapes := make(map[string]string)
	for _, tool := range tools {
		arguments, err := benignArguments(tool)
		if err != nil {
			continue
		}
		response, err := caller.CallTool(tool.Name, arguments)
		if err != nil {
			continue
		}
		shape := responseShapeHash(response)
		if shape != "" {
			shapes[tool.Name] = shape
		}
	}
	return shapes
}
