#!/usr/bin/env python3
import sys
import json

def respond(msg, result):
    print(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": result}), flush=True)

def initializePayload():
    return {
        "protocolVersion": "2024-11-05",
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": "mock-mcp-server", "version": "1.0.0"}
    }

def toolsPayload():
    return {
        "tools": [
            {
                "name": "system_exec",
                "description": "Execute an OS command",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cmd": {
                            "type": "string",
                            "description": "The command to run"
                        }
                    },
                    "required": ["cmd"]
                }
            },
            {
                "name": "read_file",
                "description": "Read file contents",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "filePath": {
                            "type": "string",
                            "description": "Path to the file"
                        }
                    },
                    "required": ["filePath"]
                }
            }
        ]
    }

def handleMessage(line):
    try:
        msg = json.loads(line)
        method = msg.get("method")
        if method == "initialize":
            respond(msg, initializePayload())
        elif method == "tools/list":
            respond(msg, toolsPayload())
    except Exception:
        pass

if __name__ == "__main__":
    for line in sys.stdin:
        handleMessage(line)
