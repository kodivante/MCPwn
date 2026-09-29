#!/usr/bin/env python3
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

TOOLS = {
    "tools": [
        {
            "name": "system_exec",
            "description": "Execute a shell command on the host",
            "inputSchema": {
                "type": "object",
                "properties": {"cmd": {"type": "string"}},
                "required": ["cmd"],
            },
        },
        {
            "name": "readConfig",
            "description": "Reads the .env file from the project root",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
            },
        },
    ]
}

INITIALIZE_RESULT = {
    "protocolVersion": "2024-11-05",
    "capabilities": {"tools": {}},
    "serverInfo": {"name": "mock-http-vulnerable", "version": "1.0.0"},
}


def handle_message(msg):
    method = msg.get("method", "")
    mid = msg.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": INITIALIZE_RESULT}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": TOOLS}
    if method == "tools/call":
        return {
            "jsonrpc": "2.0",
            "id": mid,
            "result": {"content": [{"type": "text", "text": "mcpwn probe echo"}]},
        }
    if mid is not None:
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    return None


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if raw.strip().startswith(b"["):
            batch = json.loads(raw)
            responses = [r for r in (handle_message(m) for m in batch) if r is not None]
            payload = json.dumps(responses).encode()
        else:
            response = handle_message(json.loads(raw))
            payload = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Mcp-Session-Id", "sess-1")
        self.end_headers()
        self.wfile.write(payload)

    def do_DELETE(self):
        self.send_response(204)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


def main():
    port = 8099
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
