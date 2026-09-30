#!/usr/bin/env python3
import json
import sys

TOOLS = [
    {
        "name": "greet",
        "description": "Greet a user by name",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string", "description": "The user name"}},
            "required": ["name"],
            "additionalProperties": False,
        },
    },
    {
        "name": "readManifest",
        "description": "Read the packaged manifest",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
]

INITIALIZE_RESULT = {
    "protocolVersion": "2024-11-05",
    "capabilities": {"tools": {}},
    "serverInfo": {"name": "lab-benign", "version": "1.0.0"},
}


class _ToolRegistry:
    def tool(self, fn=None):
        if fn is None:
            return lambda handler: handler
        return fn


mcp = _ToolRegistry()


@mcp.tool()
def greet(name):
    return buildGreeting(name)


def buildGreeting(subject):
    return "hello " + subject


@mcp.tool()
def readManifest():
    with open("manifest.json") as handle:
        return handle.read()


HANDLERS = {"greet": greet, "readManifest": readManifest}


def respond(msg, result):
    print(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": result}), flush=True)


def handleMessage(line):
    try:
        msg = json.loads(line)
        method = msg.get("method")
        if method == "initialize":
            respond(msg, INITIALIZE_RESULT)
        elif method == "tools/list":
            respond(msg, {"tools": TOOLS})
        elif method == "tools/call":
            params = msg.get("params", {})
            handler = HANDLERS.get(params.get("name"))
            if handler is None:
                respond(msg, {"content": [{"type": "text", "text": "unknown tool"}], "isError": True})
                return
            output = handler(**params.get("arguments", {}))
            respond(msg, {"content": [{"type": "text", "text": output}]})
    except Exception:
        pass


if __name__ == "__main__":
    for line in sys.stdin:
        handleMessage(line)
