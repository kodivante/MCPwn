# Changelog

All notable releases of MCPwn are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and semantic versioning.

## [3.21.0] - 2026-09-30

The Deep Analysis release: interprocedural taint tracking, source-to-runtime correlation and an evidence-backed attack graph. The static layer stops finding sinks and starts tracing how tool input reaches them.

### Added
- Taint engine (`internal/taint`, under `-source`): pure-Go interprocedural analysis over Python/JS/TS that identifies MCP tool handlers as sources (FastMCP-style `@mcp.tool()` decorators and `server.tool("name", handler)` registrations), propagates taint through assignments, returns and positional call arguments across function boundaries, and reports `SourceTaint01` (HIGH) with the complete call path to the sink for exec, network, filesystem, database and deserialization sinks: `runReport (server.py:46) -> executeShell (server.py:48) -> subprocess.run (server.py:54)`. Constant sink arguments never fire and recursion terminates through visited-state memoization.
- Source-to-runtime correlation (`internal/correlation`): when a static taint path matches a dynamically confirmed finding on the same tool (fuzzer marker, SSRF canary, mutation evidence), `CorrelatedVuln01` (CRITICAL, confirmed) merges both proofs into one finding: `static path: runReport -> executeShell -> subprocess.run | runtime: CmdInjection01 confirmed`. A vulnerability traced in source code and reproduced at runtime is no longer a hypothesis.
- Evidence-backed attack graph: parameter and sink nodes join tools and capabilities, with `receives` and `reaches` edges carrying per-edge evidence. `-output=graph` now models real data flow — `tool -> parameter -> sink` — with the traced path attached to every edge.
- Campaign runner: taint findings generate hypotheses tested by runtime confirmation probes; correlated vulnerabilities mark those hypotheses confirmed.
- Risk engine: correlated findings receive chain-level amplification.
- Validation lab (`test/fixtures/lab`): a vulnerable corpus (command execution and SSRF across multi-hop function chains, running as a live MCP server) and a benign corpus that must audit with zero findings. Both are regression-tested on every suite run, and the vulnerable lab demonstrates the full static → dynamic → correlated pipeline end to end. The taint layer's benign corpus proves false-positive resistance: sinks reached only through constant arguments stay silent.

## [3.20.0] - 2026-09-30

The Adaptive release: execution-aware mutation probing and sequence fuzzing join the deep battery.

### Added
- Mutation prober (`-mutate`): sends benign substitution payloads (`$(echo MARK)`, backticks, `${VAR}`) per string parameter and fires `MutationDiff01` (HIGH, confirmed) only when the server evaluates the syntax — the marker returns without its wrapper. Literal reflections are ignored, eliminating the false positives of length-based differential fuzzing.
- Sequence fuzzer (`-sequence`): two stateful probes over the session — `Idempotency01` (identical sequential calls to state-mutating tools returning different response structures) and `SequenceDrift01` (a benign call to one tool changing the state observed through another, bounded to six pairs).
- Both engines run under `-deep` and `-autopilot`; all three findings are confirmed with evidence and score confidence 95.
- OWASP mapping: `MutationDiff01` maps to MCP05 (command injection evidence), `Idempotency01` and `SequenceDrift01` map to MCP02 (privilege escalation surface).

## [3.19.0] - 2026-09-30

The Autopilot release: hypothesis-driven campaigns, policy gates and an optional LLM advisor that proposes leads but never verdicts.

### Added
- Campaign runner (`-autopilot`): builds a deterministic plan of hypotheses from static findings, capability profiles and server-level probes before testing; after the battery it marks each hypothesis confirmed or unproven and prints the campaign summary. The plan and outcomes also ship inside `-output=graph`.
- Policy gates (`-policy`): JSON files with `failOn` severities, `maxFindings` and `ignoreRules` enforce custom security gates; violations print after the report and force exit code 1 without touching the default severity logic.
- LLM advisor (`-advisor-endpoint`): sends strictly anonymized context (SHA-256 tool hashes, capability lists, rule IDs and severities — never names, descriptions or user data) to an optional endpoint and receives hypotheses back. Every accepted hint becomes an `AdvisorHint01` finding hard-capped at LOW severity, never confirmed, confidence 40 and clearly marked as unverified — AI-assisted assessment, never AI authority. Batch runs skip the advisor per target.
- Advisory hints keep their confidence through `applyConfidence` via the new advisory rule tier.

## [3.18.0] - 2026-09-29

The Depth release: source code analysis, supply chain auditing, OAuth authorization probing, shadow MCP discovery and four new static rules — closing OWASP MCP Top 10 coverage across MCP04, MCP07, MCP08 and MCP09.

### Added
- Source code analysis (`-source`): pure-Go scanner over Python/JS/TS trees (skipping `node_modules`, `venv`, `dist`, capped in files and size) reporting `SourceExec01` (os.system, subprocess, eval, exec, shell=True, child_process, execSync, new Function), `SourceDeserialization01` (pickle.loads, yaml.load without SafeLoader, marshal.loads, node-serialize) and `SourceSecret01` (HIGH: OpenAI-style keys, AWS keys, private key blocks, hardcoded api_key/secret/password/token literals) with file:line evidence. Runs standalone in CI (`mcpwn -source=.`) or alongside a live audit.
- Supply chain auditing (`-supply-chain`): parses requirements.txt, package.json and go.mod, queries the live OSV.dev vulnerability database per pinned dependency (`DependencyVuln01`, HIGH, confirmed with real GHSA/PYSEC identifiers), flags typosquats via Damerau-Levenshtein distance 1 from popular PyPI/npm packages (`Typosquat01`) and unpinned pip dependencies (`UnpinnedDep01`).
- OAuth authorization auditor (`-auth-audit`, HTTP transports): follows 401 WWW-Authenticate challenges into authorization server metadata, reports missing RFC 9728 metadata (`OAuthMetadata01`), absent S256 PKCE advertisement (`OAuthPkce01`) and acceptance of fabricated bearer tokens (`TokenPassthrough01`, HIGH).
- Shadow MCP discovery (`-discover`): inventories every MCP server configured on the machine across Claude Desktop, Claude Code, Cursor, VS Code and `.mcp.json` locations, classifies each as local-stdio, local-http or remote, and exports JSON inventories.
- Four new static rules: `TemplateInjection01` (MEDIUM), `UnsafeDeserialization01` (HIGH), `PrototypePollution01` (MEDIUM) and `NoSqlInjection01` (MEDIUM) — the static rule set grows to seventeen.
- OWASP coverage: MCP04 (supply chain) and MCP07 (authentication) are now covered; MCP08 and MCP09 are partial via source analysis and discovery. No OWASP MCP Top 10 item remains unplanned.

## [3.17.0] - 2026-09-29

The Graph release: an entity attack graph, multi-hop chain detection, a chain-aware risk index and approval snapshots with drift detection.

### Added
- Capability profiling (`internal/capability`): every tool is classified into exec, filesystem, network, database, state, credentials, prompt and resource capabilities from its schema, parameters and description.
- Entity attack graph (`internal/graph`): tools and capabilities become nodes connected by reach edges; `ReachFrom` answers what each tool can reach and the new `-output=graph` format exports the risk index, nodes, edges, per-tool reach and every detected chain path as JSON.
- Multi-hop chain detection (`AttackChain02`): the graph analyzer walks three-hop exploitation paths — exec + credentials + network becomes a complete exfiltration pipeline (CRITICAL when all anchors are confirmed), filesystem + credentials becomes secret harvesting, network + exec becomes remote takeover, database + credentials becomes structured data theft, and state + exec enables persistence. Severity downgrades when anchor evidence is only static.
- Risk engine (`internal/risk`): every finding scored 0-100 from severity, confirmation and confidence, with chain amplification and density bonuses rolling into a server-level Risk Index (0-100, grades A-F) surfaced in terminal, HTML and batch inventories. Grade F is reserved for critical-level risk.
- Approval snapshots (`-snapshot-save`, `-snapshot-compare`): tool fingerprints (SHA-256 of description, schema and capabilities) plus response shape hashes freeze an approved state; comparing reports `ToolDrift01` — description changes (HIGH, rug-pull signal), schema changes (MEDIUM), tool additions (LOW) and removals (MEDIUM) — and `BehaviorDrift01` (MEDIUM, confirmed) when a tool's response structure changes after approval. Rug pulls are now detectable across runs and days, not just between live sessions.
- Batch inventories now carry the per-target Risk Index alongside the grade.
- `applyConfidence` now runs after chain construction so `AttackChain01/02` and drift findings carry confidence scores too.

## [3.16.0] - 2026-09-29

The Reach release: Streamable HTTP transport, batch fleet auditing, JSON-RPC transcripts, OWASP MCP Top 10 mapping and HTTP-layer threat detection.

### Added
- Streamable HTTP transport (`-transport=http`): POST JSON-RPC with optional SSE responses, `Mcp-Session-Id` handling, `Authorization` header via `-auth-header`, and session termination via DELETE. Remote and enterprise MCP servers are now auditable.
- HTTP threat engine (`-http-probe`): `HttpAuthBypass01` (unauthenticated initialize plus tools/list; HIGH when `-auth-header` proves a definitive bypass), `HttpSession01` (invalid session identifiers accepted), `HttpOrigin01` (foreign Origin accepted: CSRF and DNS-rebinding surface) and `HttpBatch01` (JSON-RPC batches accepted outside MCP semantics).
- Server-to-client request probes (`-elicitation`, `-roots`): `ElicitationAbuse01` (server can solicit user input through fake client dialogs) and `RootsProbe01` (client filesystem root enumeration capability).
- Batch mode (`-targets`): audit a fleet of MCP servers from one JSON file with per-target reports (`-outdir`), a consolidated inventory (`-file`), per-target timeouts and per-target error isolation.
- JSON-RPC transcript recorder (`-record`): every request and response logged as JSONL with timestamps for full reproducibility.
- OWASP MCP Top 10 mapping: every finding carries its `OwaspMcp` tag (MCP01-MCP10) in JSON, SARIF result properties and a coverage matrix in the HTML report.
- Static rule `ContextSharing01` (MCP10): tool metadata exposing secret file markers (`.env`, `id_rsa`, private keys) that encourage context over-sharing.

### Fixed
- Session request timeouts with poisoning: a server that stops responding now bounds every session-based engine to the fuzz timeout and marks the session unresponsive instead of hanging the audit. Full deep audits against unresponsive servers drop from unbounded to roughly forty seconds, and leaked readers can no longer swallow responses of subsequent engines.
- Race prober bounded: identical concurrent calls now use the bounded handshake and await pattern shared by every raw-connection engine, so servers that ignore `tools/call` can no longer stall the probe.
- HTTP transport `Receive` now blocks until a response is buffered, matching stdio and SSE semantics; this removes receive races that produced false-positive protocol robustness findings.

## [3.15.0] - 2026-09-29

Canonical re-release of the v3.14.0 arsenal. The Go module proxy and checksum database had already cached the v3.14.0 version against the superseded commit before its tag was corrected, and cached module versions are immutable by design. This fresh version number publishes the complete arsenal cleanly. No functional changes.

### Fixed
- `go install github.com/kodivante/MCPwn/v3/cmd/mcpwn@latest` now builds the correct code. Installing `@v3.14.0` had served the pre-arsenal tree due to proxy caching.

## [3.14.0] - 2026-09-29

The unbeatable arsenal release: eight new engines, complete MCP protocol coverage (tools, resources, prompts, sampling), attack-chain analysis and per-finding confidence scores.

### Added
- Tool rug-pull detector (`-rugpull`): re-lists tools on a fresh session and fires `ToolRugPull01` (HIGH) when descriptions change after the first listing.
- Token/secret leak detector (`-tokenleak`): scans tool responses and error messages for credentials (`sk-`, API keys, AWS keys, JWTs, bearer tokens, private keys) via `TokenLeak01` (CRITICAL).
- Sampling abuse probe (`-sampling`): detects servers accepting `sampling/createMessage`, which lets a malicious server invoke the client LLM directly — `SamplingAbuse01` (MEDIUM).
- Side-channel detector (`-side-channel`): three blind-injection signals — timing (`SideChannel01`), error differential (`SideChannel02`) and response size differential (`SideChannel03`).
- Resource traversal prober (`-restraverse`): confirms `ResourceTraversal01` (HIGH) when `resources/read` returns a marker file outside its resource root; full MCP Resources support.
- Prompt template auditor (`-prompt-audit`): `prompts/list` and `prompts/get` scanned for role manipulation and exfiltration directives — `PromptPoisoning01` (HIGH/CRITICAL); full MCP Prompts support.
- Attack-chain analyzer: always-on post-analysis linking findings into exploitation paths (RCE + credential leak, SSRF + token leak, prompt injection + SSRF, SQLi + leak, mass assignment + state mutation) via `AttackChain01`.
- Per-finding `Confidence` score (0-100): confirmed with evidence 95, static 70, behavioral 55 — machine-readable precision for CI gates and near-zero false positive workflows.
- Official Docker image support: hardened multi-stage Dockerfile (non-root user, read-only, cap-drop) plus `docker-compose.yml`.
- Community payload packs in `packs/`: `filesystem.mcpwn`, `database.mcpwn` and `kubernetes.mcpwn`, all read-only and safe by design, validated by the test suite.

## [3.13.0] - 2026-09-27

Second public release: the deep dynamic testing suite. Every engine is safe by default and never touches sensitive system files.

### Added
- Path traversal prober (`-traverse`): confirms `PathTraversal01` by reading back a fuzzer-created marker file through relative traversal payloads — `/etc/passwd` and friends stay untouched, always.
- SSRF canary (`-ssrf`): confirms `Ssrf01` with a local HTTP listener on `127.0.0.1`; the finding fires when the audited server fetches the canary URL. Zero external connections.
- Schema pollution probe (`-pollute`): confirms `MassAssignment01` by injecting an undeclared property into tool call arguments built from the declared schema.
- Lifecycle desync engine (`-desync`): `tools/list` before `initialize`, duplicate `initialize`, and re-initialization after handshake produce `StateDesync01` findings.
- Protocol fuzzer (`-protofuzz`): six malformed JSON-RPC probes (missing/wrong version, invalid id, unknown method, wrong params type, garbage protocol version) with crash and silence detection via `ProtocolRobustness01`.
- Race prober (`-race-probe`): five identical concurrent tool calls on independent connections; inconsistent outcomes produce `RaceCondition01`.
- Exhaustion probe (`-exhaust`): a bounded twenty-request burst measuring latency degradation via `ResourceExhaustion01`.
- `-deep` meta-flag enabling every dynamic engine at once and `-quick` to stop probing after the first confirmation.
- New `--- Advanced Probes ---` terminal section for protocol-level findings.
- Demo fixture upgraded with real file reads and real URL fetches for end-to-end validation of the new engines.
- Contributing guide, AI-assisted workflow documentation and comparison table against scanner-typical tools.

## [3.12.2] - 2026-09-27

### Fixed
- Module path now carries the `/v3` major version suffix required by the Go toolchain for v3.x tags, making `go install github.com/kodivante/MCPwn/v3/cmd/mcpwn@latest` work.

## [3.12.1] - 2026-09-27

First public release.

### Added
- Full MCP protocol support: handshake (`initialize`/`initialized`), `tools/list` and `tools/call` over stdio and SSE transports.
- 13 static security rules: command injection, credential leaks, tool poisoning, path traversal, SQL injection, state mutation, IDOR, SSRF, denial of service, mass assignment, prompt injection sinks, weak typing and missing required fields.
- Dynamic fuzzing engine (`-fuzz`) with benign payloads (unique echo marker, controlled sleep, self-deleting temp file), a hardcoded deny-list, single retry per probe and configurable per-probe timeout.
- Prompt injection simulator (`-prompt-inject`) with full and partial reflection classification.
- Security score A-F with SVG badge output.
- Output formats: terminal, JSON, SARIF 2.1.0, self-contained HTML report and badge.
- Watch mode (`-watch`, `-interval`) and diff mode (`-diff`).
- Didactic PoC generator (`-gen-poc`) with a safety filter that refuses forbidden primitives.
- The `.mcpwn` payload language with loading via `-payloads` and automatic `./mcpwn.d/` discovery.
- GitHub Action for CI integration with SARIF upload to the repository Security tab.
- Bilingual documentation: English README at the root and Spanish at `docs/README.es.md`.
