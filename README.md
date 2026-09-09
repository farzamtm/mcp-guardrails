# MCP Guardrails Proxy

[![CI](https://github.com/farzamtm/mcp-guardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/farzamtm/mcp-guardrails/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4.svg)](global.json)

A policy-enforcing proxy that sits between an MCP client (Claude Desktop, an
agent framework) and the MCP servers it calls, so you can see and control what
your agent actually does.

> **Status: early.** Steps 0-5 of the build plan are done: the proxy connects to
> downstream servers, aggregates their tools under a namespace, forwards calls,
> audits every one of them, and can now **refuse** them by policy. Budgets,
> approval and result scanning are next. See [the spec](mcp-guardrails-dotnet-spec.md).

## What works today

- Spawns and connects to downstream stdio MCP servers
- Aggregates `tools/list` across servers, namespaced as `<server>__<tool>`
- Routes `tools/call` to the owning server and forwards the result
- Unknown tools return a *tool error*, not a protocol error, so the model can react
- **Audits every call** to a JSONL log, including calls the proxy rejects
- **Enforces a YAML policy** — allow or deny per tool, first match wins

## Policy

Point `GUARDRAILS_POLICY` at a YAML file. No file means pure passthrough.

```yaml
rules:
  - name: allow-reads
    match:
      tool: fs__read_text_file
    decision: allow

  - name: no-writes
    match:
      tool: fs__write_file
    decision: deny
    message: >-
      Writing files is disabled in this sandbox. Show the user the change you
      would make instead of applying it.
```

The agent sees:

```text
Blocked by guardrails policy rule 'no-writes': Writing files is disabled in
this sandbox. Show the user the change you would make instead of applying it.
```

That `message` is a **prompt, not a log line**. An agent told "try limit=100"
changes approach; an agent told "denied" retries forever. Run with `--explain`
to append the full decision trail to each refusal.

Rules are first-match-wins, like firewall rules — predictable by reading top to
bottom, rather than by guessing at specificity scores. See
[`examples/filesystem-sandbox.yaml`](examples/filesystem-sandbox.yaml).

## The audit log

With no policy configured the proxy is a pure passthrough that tells you what your
agent is doing. That is the whole point of transparent-by-default: useful before
you write a single rule.

Default location `~/.mcp-guardrails/audit.jsonl`, overridable with `GUARDRAILS_AUDIT`.

```json
{"ts":"2026-09-07T07:19:30.894358+00:00","event":"tool_call","tool":"fs__write_file",
 "server":"fs","downstream_tool":"write_file",
 "arguments":{"path":"/tmp/guardrails-sandbox/probe.txt","content":"..."},
 "duration_ms":5.87,"is_error":false}
```

```bash
# What did my agent touch, and how long did it take?
jq -r '[.ts, .tool, (.duration_ms|tostring)] | @tsv' ~/.mcp-guardrails/audit.jsonl

# Only the failures
jq 'select(.is_error)' ~/.mcp-guardrails/audit.jsonl
```

## Quickstart

```bash
dotnet build
dotnet test

# Tests with coverage, enforcing the 100% gate
./scripts/coverage.sh

# See what the proxy discovered downstream
./src/McpGuardrails.Cli/bin/Debug/net10.0/McpGuardrails.Cli list-upstream

# Drive the full chain without a real client
python3 scripts/smoke.py
```

Expected:

```text
PASS  proxy advertises namespaced downstream tools
PASS  write_file forwarded downstream
PASS  read_text_file returns what we wrote
PASS  unknown tool -> tool error, not a protocol error

ALL OK
```

To use it from Claude Desktop, see [`examples/claude-desktop-config.json`](examples/claude-desktop-config.json).

## How it works

The proxy is two things at once:

```text
Claude Desktop  ──thinks it's talking to a server──►  GUARDRAILS  ──thinks it's a client──►  filesystem server
                                                          │                                  (more servers…)
                                                          └── audit / policy / approval
```

- **Server half** — `src/McpGuardrails.Cli/Program.cs` registers `WithListToolsHandler`
  and `WithCallToolHandler` instead of tools of its own.
- **Client half** — `src/McpGuardrails.Core/Upstream/UpstreamRegistry.cs` owns one
  `McpClient` per downstream server and resolves a qualified tool name to its owner.

Every guardrail in the spec becomes a filter wrapped around the call handler, using
the SDK's `McpServerFilters.Request.CallToolFilters` pipeline.

## Layout

| Path | Purpose |
| --- | --- |
| `src/McpGuardrails.Core/Upstream/` | Downstream connections, tool namespacing |
| `src/McpGuardrails.Core/Policy/` | Decisions, rules, evaluator, YAML loader |
| `src/McpGuardrails.Core/Pipeline/` | Per-call scope shared between filters |
| `src/McpGuardrails.Core/Audit/` | Audit record + channel-backed JSONL sink |
| `src/McpGuardrails.Core/Serialization/` | Source-generated JSON (AOT-safe) |
| `src/McpGuardrails.Cli/Program.cs` | Host wiring; the server half of the proxy |
| `tests/McpGuardrails.Core.Tests/` | xUnit tests, 100% line and branch on Core |
| `scripts/smoke.py` | Dependency-free MCP driver for end-to-end checks |
| `scripts/coverage.sh` | Coverage run + threshold gate, same in CI and locally |

## Testing

Three layers, each covering what the one below cannot:

| Layer | What it proves |
| --- | --- |
| Unit tests | Pure logic — namespacing, config validation, the audit sink |
| In-process integration | `UpstreamRegistry` against a **real MCP server** over in-memory streams (`InMemoryMcpServer`), so genuine JSON-RPC is exercised without spawning `npx` |
| `scripts/smoke.py` | The whole chain — driver → proxy → spawned Node server → disk → audit log |

Core sits at **100% line and branch coverage**, enforced as a ratchet by
`scripts/coverage.sh` in CI. Generated code (regex and JSON source generators)
and the CLI host wiring are excluded — counting generated lines would measure
the generators rather than the tests, and a composition root is better covered
end to end than by asserting on its wiring.

## Notes for the curious

**stdout is the JSON-RPC wire.** All logging is forced to stderr. A single stray
`Console.WriteLine` corrupts the protocol stream and the client dies with a
confusing parse error. This is the most common way to break an stdio MCP server.

**Down-level servers still exist.** The official Node filesystem server does not
implement the 2026-07-28 discovery flow; you'll see a benign
`server/discover: Method not found` on stderr as the SDK falls back to the older
`initialize` handshake. Supporting both eras is a real requirement, not a wart.

**`McpClientTool.WithName()` is a trap for proxies.** It renames the client-side
wrapper but not the underlying `ProtocolTool`, so `tools/list` advertises the old
name while `tools/call` expects the new one. `ToolNamespacer.Qualify(string, Tool)`
copies the DTO properly; there's a regression test pinning it.

**Audit backpressure is deliberate.** The sink hands records to a bounded channel
so tool calls never wait on disk, but when that buffer fills producers *wait*
rather than drop. For a security tool, "no record exists" and "nothing happened"
must not be indistinguishable. Dropping would keep the agent fast at the cost of
losing evidence; that is the wrong trade here.

**Audit is the outermost filter.** Filters nest like onion layers and the first
registered is the outermost, so audit wraps everything. That ordering is what lets
it record calls that policy, budget or approval later reject.

**AsyncLocal flows down, never up.** The audit filter is outermost but the
decision it logs is made by the policy filter inside it. An inner filter
reassigning an `AsyncLocal` would be invisible to the outer one, so
`GuardrailsCallScope` publishes a mutable holder that inner filters *mutate*
instead.

**Policy loading avoids reflection on purpose.** YamlDotNet's `Deserializer`
binds via reflection, which Native AOT trims — it would yield a policy with no
rules, silently allowing everything. So YAML is parsed to a `JsonNode` tree and
bound by the source-generated deserializer instead.

**Two fail-open bugs, both caught by tests.** Property initializers are ignored
by source-generated deserialization, so an omitted `decision:` arrived as
`Verdict.Allow` (the enum's zero value) — a blocking rule would have permitted.
And `File.Exists()` returns false for a *directory*, so a policy path pointing at
one fell through to "no policy". A security component has to fail closed; both
now do, with regression tests.

## Requirements

- .NET 10 SDK
- Node.js (only to run the downstream filesystem server via `npx`)
- Python 3 (only for `scripts/smoke.py`)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the branching and commit conventions.

## Security

The [threat model](SECURITY.md) documents what this defends against and, just as
importantly, what it does not. Please report vulnerabilities privately rather
than in a public issue.

## Licence

[Apache-2.0](LICENSE).
