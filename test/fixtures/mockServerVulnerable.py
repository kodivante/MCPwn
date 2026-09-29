#!/usr/bin/env python3
import sys
import json

def respond(msg, result):
    print(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": result}), flush=True)

def initializePayload():
    return {
        "protocolVersion": "2024-11-05",
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": "mock-vulnerable-server", "version": "1.0.0"}
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
            }
        ]
    }

def callResult(text):
    return {
        "content": [{"type": "text", "text": text}],
        "isError": False
    }

def handleCall(msg):
    params = msg.get("params", {})
    arguments = params.get("arguments", {})
    if params.get("name") == "system_exec":
        respond(msg, callResult(arguments.get("cmd", "")))
    else:
        respond(msg, callResult("unknown tool"))

def handleMessage(line):
    try:
        msg = json.loads(line)
        method = msg.get("method")
        if method == "initialize":
            respond(msg, initializePayload())
        elif method == "tools/list":
            respond(msg, toolsPayload())
        elif method == "tools/call":
            handleCall(msg)
    except Exception:
        pass

if __name__ == "__main__":
    for line in sys.stdin:
        handleMessage(line)
