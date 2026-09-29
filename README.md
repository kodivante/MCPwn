# MCPwn

**Security Auditor and Fuzzing Linter for the Model Context Protocol (MCP)**

MCPwn is an MCP security scanner and fuzzing toolkit for Model Context Protocol servers: it audits tool schemas with thirteen static rules, fuzzes the JSON-RPC protocol, and confirms command injection, path traversal, SSRF, mass assignment, prompt injection, race conditions and denial-of-service risks with benign payloads — then grades every server from A to F.

Designed and developed by **kodivante**

**Read this in Spanish:** [docs/README.es.md](docs/README.es.md)

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE) [![Go Version](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://golang.org) [![Security Standard](https://img.shields.io/badge/Security-Audit_Ready-brightgreen)](#) [![CI](https://github.com/kodivante/MCPwn/actions/workflows/ci.yml/badge.svg)](https://github.com/kodivante/MCPwn/actions/workflows/ci.yml)

---

## Story

MCPwn was born during an authorized red team engagement, in the first months of the Model Context Protocol. Kodivante was auditing AI infrastructure, and the same finding appeared everywhere: MCP servers listening on the network with tools that trusted every input — raw command execution offered to any model polite enough to ask, file readers with no path restrictions, credential fields typed straight into tool schemas.

The moment that sealed it: a client insisted their agent "only had read-only tools." One bare `tools/list` request later, the server answered with a tool described as "Execute an OS command" — one string parameter, no enum, no validation. Worse: no scanner on the market could even see the flaw. Every MCP server on that network was an unguarded API that nobody was testing.

That night, the first version of MCPwn was written. It grew into a full suite: thirteen static rules, a fuzzer that proves findings with harmless probes, a prompt injection simulator, PoC generation, a security score, and watch mode. One rule has never changed: it attacks like a red teamer and behaves like a blue teamer. Every payload is benign by design, and a hardcoded deny-list guarantees MCPwn can only ever be a detector, never a weapon. Point it at a server you do not own, and you are the vulnerability.

---

## Key Features

- **Protocol-native discovery**: full MCP handshake (`initialize`/`initialized`) over stdio or SSE, including `tools/call`, `resources/list`, `resources/read`, `prompts/list` and `prompts/get`.
- **13 static security rules**: command injection, path traversal, SSRF, credential leaks, SQL injection, denial of service, state mutation, tool poisoning, IDOR, mass assignment, weak typing, missing required fields, and prompt injection sinks.
- **Deep dynamic testing suite** (`-deep`): fifteen engines — path traversal prober, SSRF canary, schema pollution probe, lifecycle desync, protocol fuzzer, race prober, exhaustion probe, tool rug-pull detector, token leak scanner, sampling abuse probe, side-channel detector, resource traversal prober and prompt template auditor.
- **Attack-chain analysis**: always-on post-analysis that links findings into exploitation paths (RCE + credential leak, SSRF + token leak, prompt injection + SSRF) and reports the full chain with evidence.
- **Per-finding confidence**: every finding carries a 0-100 `Confidence` score — confirmed-with-evidence findings score 95, static detections 70 — enabling near-zero false positive CI gates.
- **Dynamic fuzzing engine**: confirms command injection findings by sending benign payloads (echo with a unique marker, controlled sleep, self-deleting temp file) with a strict hardcoded deny-list.
- **Prompt injection simulator**: sends three fixed benign payloads and classifies full or partial reflection of user input.
- **Security score**: every audit collapses into a grade from A (clean) to F (critical).
- **Outputs**: terminal, JSON, SARIF (CI-ready), self-contained light-theme HTML report (ZAP-inspired), and SVG badge.
- **Watch and diff modes**: continuous re-auditing on an interval, and regression comparison against a baseline report.
- **PoC generator**: didactic, reproducible Python/Bash proof-of-concept scripts for confirmed findings — with a safety filter that refuses to emit forbidden primitives.
- **Payload plugins**: extend the fuzzer with your own payloads in the `.mcpwn` DSL.
- **Pure Go stdlib**: zero external dependencies.

---

## Installation

```bash
go install github.com/kodivante/MCPwn/v3/cmd/mcpwn@latest
```

Or from source:

```bash
git clone https://github.com/kodivante/MCPwn
cd MCPwn
go build -o mcpwn ./cmd/mcpwn
```

---

## Quick Start

Audit a local MCP server running via stdio:

```bash
mcpwn -transport=stdio -command=node -args=server.js
```

Audit an MCP server over SSE:

```bash
mcpwn -transport=sse -url=http://localhost:8080/sse
```

Full battery: static audit, dynamic fuzzing confirmation, prompt injection simulation, and PoC generation:

```bash
mcpwn -transport=stdio -command=python3 -args=server.py -fuzz -prompt-inject -gen-poc
```

See the full HTML report against our intentionally vulnerable demo server (33 findings, grade F):

```bash
mcpwn -transport=stdio -command=python3 -args=test/fixtures/mockServerDemo.py -fuzz -prompt-inject -output=html -file=report.html
```

Run the complete deep battery: every static rule, every dynamic engine, everything:

```bash
mcpwn -transport=stdio -command=python3 -args=test/fixtures/mockServerDemo.py -deep
```

---

## CLI Reference

| Flag | Default | Description |
|---|---|---|
| `-transport` | `stdio` | Transport type: `stdio` or `sse` |
| `-command` | — | Command to run for stdio transport |
| `-args` | — | Command arguments, comma separated |
| `-url` | — | URL for SSE transport |
| `-output` | `terminal` | Output format: `terminal`, `json`, `sarif`, `html`, `badge` |
| `-file` | — | Write output to file instead of stdout |
| `-timeout` | `30s` | Per-audit timeout |
| `-fuzz` | `false` | Run dynamic fuzzing to confirm command injection findings |
| `-fuzz-timeout` | `10s` | Per-probe fuzz timeout |
| `-prompt-inject` | `false` | Simulate prompt injection with benign payloads |
| `-gen-poc` | `false` | Generate PoC scripts for confirmed findings into `./pocs` |
| `-poc-lang` | `python` | PoC language: `python` or `bash` |
| `-payloads` | — | Custom fuzz payload file or directory (`.mcpwn`) |
| `-watch` | `false` | Re-audit continuously on an interval (Ctrl+C to stop) |
| `-interval` | `30s` | Watch mode interval |
| `-diff` | — | Baseline JSON report to compare against |
| `-deep` | `false` | Enable every dynamic engine in one flag |
| `-quick` | `false` | Stop deep probing after the first confirmed finding |
| `-traverse` | `false` | Confirm path traversal findings with a marker file |
| `-ssrf` | `false` | Confirm SSRF findings with a local canary listener |
| `-pollute` | `false` | Confirm mass assignment findings with undeclared properties |
| `-desync` | `false` | Probe MCP lifecycle state handling |
| `-protofuzz` | `false` | Send malformed JSON-RPC messages and detect crashes |
| `-race-probe` | `false` | Send identical concurrent tool calls |
| `-exhaust` | `false` | Measure latency degradation under a bounded request burst |
| `-rugpull` | `false` | Detect tool description changes across sessions |
| `-tokenleak` | `false` | Scan tool responses and errors for leaked credentials |
| `-sampling` | `false` | Detect if server accepts sampling/createMessage |
| `-side-channel` | `false` | Detect blind injection via timing, size and error side-channels |
| `-restraverse` | `false` | Probe resources/read with traversal payloads |
| `-prompt-audit` | `false` | Audit prompt templates for hidden instructions and exfiltration |
| `-version` | — | Print version and exit |

**Exit codes**: `0` when no CRITICAL or HIGH findings, `1` otherwise. Any operational error also exits `1` with a message on stderr.

---

## Static Rules

| Rule | Severity | Detects |
|---|---|---|
| `CmdInjection01` | CRITICAL | String parameters allowing raw command execution without enum restrictions |
| `CredentialsLeak01` | CRITICAL | Parameters asking the LLM for raw credentials (token, apiKey, secret, password) |
| `ToolPoisoning01` | CRITICAL | Adversarial instructions embedded in tool names or descriptions |
| `PathTraversal01` | HIGH | Path parameters without sanitization against directory traversal |
| `SqlInjection01` | HIGH | Parameters accepting raw SQL queries |
| `StateMutation01` | HIGH | Destructive tools (delete/update) without a confirmation parameter |
| `Idor01` | HIGH | User-supplied resource IDs without restrictions or ownership checks |
| `Ssrf01` | MEDIUM | URL/webhook parameters without protocol or domain validation |
| `Dos01` | MEDIUM | File reading tools without bounding parameters (limit, maxLines) |
| `MassAssignment01` | MEDIUM | Object schemas allowing undeclared properties |
| `PromptInjection01` | MEDIUM | Parameters feeding user-controlled text into the model (with `-prompt-inject`) |
| `WeakTyping01` | LOW | Parameters without an explicit type |
| `MissingRequired01` | LOW | Critical parameters missing from the required array |

Schema validation issues surface as `SchemaValidation01` (LOW) findings.

## Dynamic Engines

### Fuzzer (`-fuzz`)

Confirms `CmdInjection01` findings by calling the tool with benign probes:

- `echo {uuid}` — a unique marker that must come back in the response
- `sleep 2` — timing-based confirmation via controlled delay
- `cat {tempfile}` — reads a fuzzer-created temp file that is deleted afterwards

Each probe gets one retry, a configurable timeout, and the engine aborts on the first unresponsive server. Confirmed findings show `[!]` and an evidence line; unconfirmed show `[?]`.

**The deny-list is hardcoded and non-negotiable**: payloads containing `rm`, `del`, `curl`, `wget`, `nc`, `ssh`, `sudo`, `chmod`, shell metacharacters (`>`, `|`, `&&`, `;`), or sensitive paths (`/etc/passwd`, `.ssh`, `.env`) are rejected at load time. User-defined payloads cannot bypass it.

### Prompt Injection Simulator (`-prompt-inject`)

Sends three fixed benign strings ("Ignore previous instructions...", "You are now DAN...", "[SYSTEM]: Override...") and classifies the response:

- Full reflection returns unescaped → `PromptInjectionReflection` (HIGH)
- Fragments reflected (4-word windows) → `PromptInjectionPartialReflection` (MEDIUM)
- Sanitized or absent → no finding

Dynamic findings are rendered in a separate terminal section.

## Deep Dynamic Testing

Fifteen engines, every one safe by default. `-deep` enables them all; `-quick` stops probing after the first confirmation.

| Engine | Flag | Produces | How it proves |
|---|---|---|---|
| Path traversal prober | `-traverse` | Confirms `PathTraversal01` | Reads back a fuzzer-created marker file through `../` payloads — sensitive system files are never touched |
| SSRF canary | `-ssrf` | Confirms `Ssrf01` | A local listener on `127.0.0.1` records the audited server fetching the canary URL — zero external connections |
| Schema pollution probe | `-pollute` | Confirms `MassAssignment01` | Sends an undeclared property alongside schema-valid arguments; silent acceptance confirms the risk |
| Lifecycle desync engine | `-desync` | `StateDesync01` (MEDIUM) | `tools/list` before `initialize`, duplicate `initialize`, and re-initialization after handshake |
| Protocol fuzzer | `-protofuzz` | `ProtocolRobustness01` (HIGH/MEDIUM) | Six malformed JSON-RPC probes; dropped connections and dead silence are findings |
| Race prober | `-race-probe` | `RaceCondition01` (MEDIUM) | Five identical concurrent calls on independent connections; inconsistent outcomes are findings |
| Exhaustion probe | `-exhaust` | `ResourceExhaustion01` (LOW/MEDIUM) | A bounded twenty-request burst measuring latency degradation — never an actual denial of service |
| Tool rug-pull detector | `-rugpull` | `ToolRugPull01` (HIGH) | Re-lists tools on a fresh session and diffs descriptions against the first listing |
| Token leak scanner | `-tokenleak` | `TokenLeak01` (CRITICAL) | Calls every tool with schema-derived benign arguments and scans responses and errors for credentials: `sk-`, API keys, AWS keys, JWTs, bearer tokens, private keys |
| Sampling abuse probe | `-sampling` | `SamplingAbuse01` (MEDIUM) | Sends `sampling/createMessage` on a fresh connection; acceptance means the server can invoke your LLM directly |
| Side-channel detector | `-side-channel` | `SideChannel01/02/03` | Baselines a benign call per tool, then measures timing, error-differential and response-size deviations — blind injection without payload reflection |
| Resource traversal prober | `-restraverse` | `ResourceTraversal01` (HIGH) | Full MCP Resources coverage: probes `resources/read` URIs with marker files outside the resource root |
| Prompt template auditor | `-prompt-audit` | `PromptPoisoning01` (HIGH/CRITICAL) | Full MCP Prompts coverage: `prompts/list` and `prompts/get` templates scanned for role manipulation (`ignore previous instructions`) and exfiltration directives (URLs, webhooks, upload targets) |
| Attack-chain analyzer | always on | `AttackChain01` (HIGH/CRITICAL) | Links findings into exploitation paths: RCE + credential leak becomes full host takeover; SSRF + token leak becomes lateral movement — each chain reports its links with evidence |
| Dynamic fuzzer | `-fuzz` | Confirms `CmdInjection01` | Benign echo/sleep/temp-file payloads with a strict deny-list (`rm`, `curl`, `wget`, `nc`, `ssh`, `sudo` are hardcoded-rejected) |
| Prompt injection simulator | `-prompt-inject` | `PromptInjection01` | Three fixed benign payloads classified as full or partial reflection |

Every confirmed finding carries a `Confidence` score (0-100): confirmed with evidence scores 95, static detections 70, behavioral side-channel detections 55. Machine-readable in JSON and SARIF for CI gates.

Protocol-level findings are rendered in the `--- Advanced Probes ---` terminal section so they never mix with tool findings.

---

## Docker

```bash
docker build -t mcpwn .
docker run --rm -v "$PWD":/audit mcpwn -transport=stdio -command=python3 -args=/audit/server.py -deep
```

The image is hardened: multi-stage build, non-root user, read-only filesystem and dropped capabilities via the included `docker-compose.yml`.

---

## Community Packs

Ready-made `.mcpwn` payload packs live in [`packs/`](packs/):

| Pack | Probes |
|---|---|
| `filesystem.mcpwn` | Command execution and arbitrary file read with scanner-created temp files |
| `database.mcpwn` | Read-only SQL injection probes (sqlite version, UNION, comment break) |
| `kubernetes.mcpwn` | kubectl client version, namespace listing, environment exposure |

Use them with `-payloads=packs/kubernetes.mcpwn` or drop any `.mcpwn` file into `./mcpwn.d/` for auto-discovery.

---

## AI-Assisted Workflow

MCPwn output is designed for AI-driven triage:

```bash
mcpwn -transport=stdio -command=python3 -args=server.py -deep -output=json -file=findings.json
```

1. Run the automated baseline: static linting plus every dynamic engine, with confirmations and evidence attached to each finding.
2. Feed `findings.json` to your AI assistant: severity, remediation, `Confirmed` and `Evidence` fields remove speculation from the analysis.
3. The AI validates findings in context, chains them into attack paths, and drafts fixes — over facts, not guesses.

Automated baseline (MCPwn) plus deep contextual analysis (your AI) equals complete security coverage.

---

## Why MCPwn

| Capability | Typical MCP scanners | MCPwn |
|---|---|---|
| Static schema linting | Rare | 13 rules with remediation guidance |
| Dynamic confirmation | Destructive by default, needs a safe mode | Safe by default — no safe mode exists because nothing destructive ships |
| Sensitive files during traversal tests | Reads `/etc/passwd`, private keys | Never — only fuzzer-created marker files |
| Out-of-band detection | External DNS/callback servers | Local `127.0.0.1` canary, zero external connections |
| PoC generation | — | Didactic Python/Bash with a safety filter |
| Security score | — | A–F grade plus SVG badge |
| Watch and diff modes | — | Built-in |
| Payload extensibility | — | `.mcpwn` DSL with auto-loading directory |
| Install | Clone, chmod, Python runtime | Single Go binary via `go install` |
| CI integration | Documentation only | GitHub Action with SARIF upload |

---

## Outputs

- **terminal**: colored report with `[!]`/`[?]` indicators, remediation, evidence, and the security score.
- **json**: findings array (empty audits emit `[]`, confirmed findings carry `Confirmed` and `Evidence`).
- **sarif**: SARIF 2.1.0 with driver version, ready for GitHub Security tab.
- **html**: single self-contained light-theme report (ZAP-inspired) with a dashboard, severity sections, and confirmation badges. No JS, no external assets.
- **badge**: shields-style SVG with your grade (green A through red F) for your README.

## Security Score

Based on severity counts:

| Grade | Condition |
|---|---|
| A | No CRITICAL or HIGH findings |
| B | 1–2 HIGH |
| C | 3+ HIGH |
| D | 1–2 CRITICAL |
| F | 3+ CRITICAL |

## Watch Mode

```bash
mcpwn -transport=stdio -command=python3 -args=server.py -watch -interval=10s
```

Runs the audit, clears the screen, and re-audits on every tick. Each audit gets its own timeout; the loop runs until Ctrl+C and shuts down gracefully even mid-audit.

## Diff Mode

Compare a run against a previous JSON report:

```bash
mcpwn -transport=stdio -command=python3 -args=server.py -output=json -file=baseline.json
mcpwn -transport=stdio -command=python3 -args=server.py -diff=baseline.json
```

The diff report (on stderr) lists New, Fixed, and Unchanged findings keyed by rule + tool + path.

## PoC Generation

```bash
mcpwn -transport=stdio -command=python3 -args=server.py -fuzz -gen-poc
```

For every **confirmed** finding, writes `./pocs/<finding_id>_<tool>.py` (or `.sh` with `-poc-lang=bash`): a self-contained, pipe-based script that replays the handshake and the benign probe. The generated PoC contains a mandatory header (tool, finding, severity, evidence, authorized-use disclaimer), a success marker, and the remediation as a final comment. A safety filter refuses to generate any PoC containing `curl`, `subprocess`, `os.system`, sockets, or similar primitives.

```bash
python3 pocs/CmdInjection01_system_exec.py | python3 server.py
```

---

## The `.mcpwn` Payload Language

Extend the fuzzer with your own probes. Payloads are added to the built-ins and go through the same deny-list:

```ini
# mypayloads.mcpwn
payload "custom_echo" {
    rule        = CmdInjection01
    template    = "echo probe_{uuid}"
    expect      = "probe_{uuid}"
    delay       = 2s
    description = "Confirms execution with a custom marker"
}
```

| Field | Required | Meaning |
|---|---|---|
| `rule` | yes | Target rule ID (e.g. `CmdInjection01`) |
| `template` | yes | Payload text; `{uuid}` becomes a unique marker, `{tempfile}` a fuzzer-created temp file |
| `expect` | no | Marker that must appear in the response to confirm |
| `delay` | no | Timing threshold for delay-based confirmation |
| `description` | no | Human-readable intent |

Loading: `-payloads=file.mcpwn` (or a directory), plus automatic loading of every `.mcpwn` inside `./mcpwn.d/` when it exists. Deny-list violations are rejected with a warning and the rest of the file still loads; syntax errors abort that file. See [examples/](examples/) for ready-to-use payload packs.

---

## GitHub Action

Use the audit in any repository's workflow:

```yaml
- uses: kodivante/MCPwn@main
  with:
    transport: stdio
    command: python3
    args: server.py
    output: sarif
    file: mcpwn-results.sarif
```

With `output: sarif` the results upload to the repository's Security tab automatically.

---

## Architecture

```
cmd/mcpwn/            CLI entrypoint (flag parsing only)
internal/app/         orchestration: connect, audit, fuzz, prompt-inject, deep probes, report, exit code
internal/auditor/     rule engine + 13 static rules
internal/client/      JSON-RPC 2.0: stdio, SSE, session, handshake
internal/fuzzer/      dynamic fuzzing + .mcpwn DSL parser
internal/promptinject prompt injection simulator
internal/traversal/   path traversal prober
internal/ssrfcanary/  local SSRF canary listener
internal/pollution/   schema pollution probe
internal/desync/      lifecycle desync engine
internal/protocolfuzz/ JSON-RPC protocol fuzzer
internal/raceprober/  concurrent race probe
internal/exhaustion/  latency degradation probe
internal/pocgen/      PoC generator with safety filter
internal/reporter/    JSON / SARIF / HTML / badge outputs
internal/scorer/      A-F security grade
internal/schema/      JSON Schema parser + validator
internal/ui/          terminal renderer
internal/version/     single source of version truth
```

## Development

```bash
go build ./... && go vet ./... && go test ./... -race -cover
```

Coverage floor: 80% on `internal/schema` and `internal/auditor`. Zero external dependencies, strict typing, no emojis, no underscores outside `_test.go`.

Contributions are welcome — open an issue or pull request.

---

## Legal Disclaimer

MCPwn is designed and developed exclusively for authorized security auditing, educational research, and defensive hardening of Model Context Protocol (MCP) implementations. The developers and contributors assume no liability and are not responsible for any misuse, damage, or unauthorized testing conducted with this software. Using this tool against targets without prior written authorization from the system owners is strictly prohibited and may violate local and international laws. By using MCPwn, you agree that you are solely responsible for your actions and compliance with all applicable regulations.
