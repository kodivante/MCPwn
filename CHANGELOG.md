# Changelog

All notable releases of MCPwn are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and semantic versioning.

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
