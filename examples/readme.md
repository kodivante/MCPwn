# Payload Examples

Ready-to-use packs for the `.mcpwn` payload language.

## Usage

Load a single pack:

```bash
mcpwn -transport=stdio -command=python3 -args=server.py -fuzz -payloads=examples/echoProbe.mcpwn
```

Or drop any `.mcpwn` file into `./mcpwn.d/` next to your terminal and it loads automatically on every fuzz run.

## Packs

- `echoProbe.mcpwn` — confirms command execution with a custom echo marker.
- `timingProbe.mcpwn` — confirms command execution via a controlled response delay.

Every payload passes through the hardcoded deny-list; anything destructive or exfiltrating is rejected at load time.
