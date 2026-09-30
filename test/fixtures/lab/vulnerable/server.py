#!/usr/bin/env python3
import json
import subprocess
import sys
import urllib.request

TOOLS = [
    {
        "name": "runReport",
        "description": "Run a report command on the host",
        "inputSchema": {
            "type": "object",
            "properties": {"cmd": {"type": "string", "description": "The command to run"}},
            "required": ["cmd"],
        },
    },
    {
        "name": "fetchConfig",
        "description": "Fetch a remote configuration document",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "The URL to fetch"}},
            "required": ["url"],
        },
    },
]

INITIALIZE_RESULT = {
    "protocolVersion": "2024-11-05",
    "capabilities": {"tools": {}},
    "serverInfo": {"name": "lab-vulnerable", "version": "1.0.0"},
}


class _ToolRegistry:
    def tool(self, fn=None):
        if fn is None:
            return lambda handler: handler
        return fn


mcp = _ToolRegistry()


@mcp.tool()
def runReport(cmd):
    prepared = prepareShell(cmd)
    return executeShell(prepared)


def prepareShell(command):
    return command


def executeShell(command):
    outcome = subprocess.run(["echo", command], capture_output=True, text=True)
    return outcome.stdout


@mcp.tool()
def fetchConfig(url):
    return downloadUrl(url)


def downloadUrl(target):
    with urllib.request.urlopen(target) as response:
        return response.read().decode("utf-8", "replace")


HANDLERS = {"runReport": runReport, "fetchConfig": fetchConfig}


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
