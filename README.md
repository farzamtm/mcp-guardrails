# MCP Guardrails Proxy

[![CI](https://github.com/farzamtm/mcp-guardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/farzamtm/mcp-guardrails/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4.svg)](global.json)

A policy-enforcing proxy that sits between an MCP client (Claude Desktop, an
agent framework) and the MCP servers it calls, so you can see and control what
your agent actually does.

> **Status: early.** Steps 0-8 of the build plan are done: the proxy connects to
> downstream servers, aggregates their tools under a namespace, forwards calls,
> audits every one of them, can **refuse** them by policy - matching on tool
> globs, the tool's own MCP annotations, and predicates over the arguments -
> enforces a **session budget** with per-rule costs, and can **hold a call until
> a human approves it**, at the client or through a signed webhook.
> Result scanning and the Streamable HTTP host are next.
> See [the spec](mcp-guardrails-dotnet-spec.md).

## What works today

- Spawns and connects to downstream stdio MCP servers
- Aggregates `tools/list` across servers, namespaced as `<server>__<tool>`
- Routes `tools/call` to the owning server and forwards the result
- Unknown tools return a *tool error*, not a protocol error, so the model can react
- **Audits every call** to a JSONL log, including calls the proxy rejects
- **Enforces a YAML policy** — allow or deny, first match wins, matching on tool
  name globs, MCP annotations and the call's arguments
- **Caps a session** — a maximum number of calls, or a maximum total cost with
  per-rule weights, refused with a message that tells the agent to stop
- **Asks a human** — `require_approval` puts the question to the person at the
  MCP client, or POSTs it to a signed webhook, and waits for an answer, with a
  configurable deadline

## Policy

Point `GUARDRAILS_POLICY` at a YAML file. No file means pure passthrough.

```yaml
rules:
  - name: allow-reads
    match:
      tool: fs__read_*
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
to append the full decision trail to each refusal, naming the condition that
failed on every rule considered.

Rules are first-match-wins, like firewall rules — predictable by reading top to
bottom, rather than by guessing at specificity scores. See
[`examples/filesystem-sandbox.yaml`](examples/filesystem-sandbox.yaml).

### What a rule can match on

Three kinds of condition, combined with AND. An omitted condition is skipped, so
a `match:` with nothing in it is a catch-all.

```yaml
rules:
  - name: cap-bulk-exports
    match:
      tool: ct__export_*              # glob: * any run, ? one character
      annotations:
        readOnlyHint: false           # what the tool says it does
      args:
        - path: $.limit               # what this call is asking for
          gt: 100
    decision: deny
    message: Exports over 100 rows need approval; try limit=100.
```

**Tool globs** cover a whole server (`fs__*`) or a verb across every server
(`"*__delete_*"`). A pattern with no wildcard is still an exact, case-sensitive
match, so older policy files mean exactly what they did before. Quote any
pattern that *starts* with `*` — in YAML a bare leading `*` is an alias
reference, so `tool: *__delete_*` is a parse error rather than a glob.

**Annotations** — `readOnlyHint`, `destructiveHint`, `idempotentHint`,
`openWorldHint` — match on what a tool advertises rather than what it is called,
which is how you cover the server somebody adds next month. The MCP defaults
apply, and they fail closed: a tool that declares nothing counts as destructive,
so `destructiveHint: true` catches it. These are *hints from an upstream server*,
though, so treat them as a safety net under your named rules, not as a guarantee
— a hostile server can describe its delete tool as read-only.

**Argument predicates** take a JSONPath and exactly one operator: `eq`, `gt`,
`lt`, `matches`, `prefix`, `not_prefix`, `in`. One operator per entry, so
`--explain` can name the condition that failed; two conditions on one value are
two list entries. The supported path syntax is `$.a.b`, `$.a[0]` and
`$['quoted key']` — anything else is rejected when the policy loads rather than
silently never matching.

An argument the model did not send satisfies no predicate, **including a negated
one**: `not_prefix` asserts "there is a value and it does not start with this".
A rule must not fire on evidence that was never supplied, so when a missing
argument should also be refused, follow the rule with a catch-all.

`prefix` and `not_prefix` compare the **literal argument string**. Nothing is
resolved, canonicalised or normalised, so `/workspace/../etc/passwd` starts with
`/workspace/` as far as a policy is concerned. They are good at classifying what
the model *asked for*; they cannot tell you where a path actually points.
Directory containment stays the downstream server's job — configure its allowed
roots and treat the prefix rule as the layer above it, not as a substitute.

A `matches` pattern runs under a 100 ms budget. If it is still running when the
budget expires, the rule is reported as **undecidable and the call is denied** —
whatever that rule's own decision was. Fail-open here would be a bypass anyone
could trigger: the model chooses the argument, so it could pad a value until the
rule gave up and the call fell through to default-allow. A denial of this kind
names the rule in both the refusal and the audit log, so it is visible rather
than silent.

## Budgets

A policy answers *may this call happen?*. A budget answers *how many times?* —
because the expensive agent is rarely the one making a call it should not make,
it is the one making a permitted call four thousand times in a loop.

```yaml
budgets:
  session:
    max_calls: 200      # chattiness
    max_cost: 50        # damage

rules:
  - name: reads-are-free
    match:
      annotations:
        readOnlyHint: true
    decision: allow
    cost: 0

  - name: expensive-export
    match:
      tool: ct__export_*
    decision: allow
    cost: 25
```

The agent sees:

```text
Blocked by guardrails budget 'session.max_cost': this call costs 25 and the
session has already spent 40 of its 50 budget. Stop calling tools and tell the
user the budget is exhausted; only they can raise 'budgets.session.max_cost' or
start a new session.
```

That wording is deliberate, and it is the opposite of a policy denial. "Choose a
different approach" is right when one tool is forbidden and wrong when the
session is out of money, where every approach fails and a retrying agent only
burns the user's time.

**Cost lives on the rule** that matched, because a rule already says *which
calls* precisely — tool glob, annotations, arguments. Omitted means `1`, so a
budget is meaningful before anyone writes a single `cost:`. `cost: 0` makes a
class of calls free to spend but not free to make: they still count against
`max_calls`, or a free tool would be an unbounded loop.

What gets charged, and when:

- A call the **policy refused** costs nothing. It never reached a server.
- A call **awaiting approval** costs nothing yet, for the same reason.
- A call that was **forwarded** is charged even if the server then failed.
  Refunding failures would let a broken tool be retried without limit.
- Refusals are **audited like any other denial**, with `rule` naming the cap
  (`session.max_cost`) rather than a policy rule.

**`session` means this process.** An stdio proxy is spawned per client session,
so the counters live in memory and start again with the next session. Daily caps
need a store that survives process exit; until that ships, a `budgets.daily:`
block is a **load-time error** rather than a limit that silently enforces
nothing.

## Approval

Some calls should not be decided in advance. `require_approval` holds the call
and asks the person at the MCP client:

```yaml
rules:
  - name: approve-destructive
    match:
      annotations:
        destructiveHint: true
    decision: require_approval
    approval:
      timeout_s: 300        # how long to wait; default 300
      on_timeout: deny      # what silence means; default deny
      prompt: >-
        This tool can delete data that is not backed up. Approve?
```

The client shows the prompt, the human answers, and the call either goes
downstream or comes back refused. Nothing is forwarded while the question is
open, and an approved call is charged to the budget exactly like a normal one —
approval runs *before* the budget precisely so a call waiting on a human never
spends anything.

**Silence is not consent.** The default `on_timeout: deny` exists because the
usual reason nobody answered is that nobody was looking, which is exactly when a
destructive call should not run. `on_timeout: allow` is available and is logged
distinctly — see below.

**A client that cannot ask is a denial, not a bypass.** Approval uses MCP
elicitation, and not every client implements it. When yours does not, a
`require_approval` rule refuses the call and says so, rather than quietly
behaving like `allow`. If that is not what you want, the honest fix is to change
the rule, not to let the gate fail open.

The audit log keeps the distinction the verdict alone destroys:

```bash
# Calls a person actually looked at and approved
jq 'select(.approval == "approved")' ~/.mcp-guardrails/audit.jsonl

# Calls that went through only because nobody answered in time
jq 'select(.approval == "timed_out" and .decision == "allow")' ~/.mcp-guardrails/audit.jsonl
```

`approval` is one of `approved`, `declined`, `timed_out`, `unavailable` or
`failed`.

### Asking a webhook instead

When nobody is sitting at the client — an autonomous agent, a CI job — send the
question to an HTTP endpoint you run, which can page someone, post to a chat
room, or consult a ticketing system:

```yaml
approvers:
  webhook:
    url: https://approvals.example.com/hooks/guardrails
    secret_env: GUARDRAILS_WEBHOOK_SECRET   # the variable's NAME, never the secret

rules:
  - name: approve-deletes
    match:
      tool: "*__delete_*"
    decision: require_approval
    approval:
      mode: webhook
      timeout_s: 600
```

The endpoint is configured once, under `approvers:`, and each rule chooses
`mode: in_band` (the default) or `mode: webhook`. A webhook rule without an
`approvers.webhook` section is a load-time error.

**The protocol is one POST, answered synchronously.** The proxy sends:

```text
POST /hooks/guardrails
Content-Type: application/json; charset=utf-8
X-Guardrails-Signature: sha256=<hex HMAC-SHA256 of the raw body>
X-Guardrails-Request-Id: 8e0f3c2b9a7d4c51b6a2f0e1d3c4b5a6
```

```json
{
  "version": 1,
  "request_id": "8e0f3c2b9a7d4c51b6a2f0e1d3c4b5a6",
  "tool": "fs__delete_file",
  "server": "fs",
  "rule": "approve-deletes",
  "question": "Allow the agent to call 'fs__delete_file'? Guardrails rule 'approve-deletes' requires your approval.",
  "arguments": { "path": "/srv/reports/q3.csv" },
  "sent_at": "2026-10-01T12:00:00+00:00",
  "deadline": "2026-10-01T12:10:00+00:00"
}
```

(sent on one line; `server` and `arguments` are omitted when there are none) and
holds the request open until the endpoint replies `200 OK` with:

```json
{ "request_id": "8e0f3c2b9a7d4c51b6a2f0e1d3c4b5a6", "decision": "approve" }
```

`"decision": "deny"` refuses the call. That is the whole contract. A receiver
that has to wait for a person keeps the connection open until they answer, or
until `deadline`, after which the proxy has stopped listening anyway. Polling a
status URL was considered and rejected: it adds a second, remotely supplied URL
that would need its own scheme, host and signature checks, to buy something a
receiver can do internally.

Argument values are sent as strings and cut at 256 characters — an approver
needs to see *which* path, not the 40 KB being written to it. They are otherwise
exactly what the model sent, so run the endpoint somewhere you would be
comfortable storing them.

**Verify the signature before you parse the body.** Compute
`HMAC-SHA256(secret, raw body bytes)`, hex-encode it, and compare it with the
header value after `sha256=` in constant time; use `sent_at` to reject replays
older than you are willing to accept. The proxy reads the secret from the
variable named by `secret_env` when it starts serving, and refuses to start if
it is unset or empty rather than send requests anyone could forge. Generate one
with `openssl rand -hex 32`.

**Everything except a clean answer is a denial.** A status other than `200`, a
redirect (never followed — it would send the signed body somewhere the policy
did not name), a body that does not parse, a `request_id` that does not match
the question, any decision other than exactly `approve` or `deny`, a refused
connection or a TLS failure: each is logged as `approval: "failed"` and the call
is refused. Only the rule's own `timeout_s` produces `timed_out`, so
`on_timeout` means the same for a webhook as for a person at the client —
including that `on_timeout: allow` lets a call through when an endpoint *hangs*,
whereas one that is down refuses the connection and fails closed.

**HTTPS is required.** For a receiver on the same machine during development,
`allow_insecure_localhost: true` permits plain `http://` to a loopback address
(`localhost`, `127.0.0.1`, `::1`) and nothing else. Credentials in the URL are
rejected; the signature is the authentication.

See [`examples/webhook-approval.yaml`](examples/webhook-approval.yaml), and
`scripts/smoke.py` for a 40-line receiver that verifies the signature.

**Not implemented yet:** `mode: slack` is rejected at load time rather than
silently ignored, for the same reason `budgets.daily:` is. The Tasks/MRTR path
the spec prefers — returning an `input_required` task instead of holding the
request open — lands behind the same `IApprovalChannel` seam.

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
| `ruff.toml` | Lint settings for the Python tooling |

## Testing

Three layers, each covering what the one below cannot:

| Layer | What it proves |
| --- | --- |
| Unit tests | Pure logic — namespacing, config validation, the audit sink |
| In-process integration | `UpstreamRegistry` against a **real MCP server** over in-memory streams (`InMemoryMcpServer`), so genuine JSON-RPC is exercised without spawning `npx` |
| `scripts/smoke.py` | The whole chain — driver → proxy → spawned Node server → disk → audit log, in two phases: pure passthrough, then a policy that denies by glob, by argument, by annotation, and by failing closed on a guardrail it could not finish checking; then budgets, approval at the client, and approval through a local webhook receiver that verifies the signature |

CI runs all three on Linux, macOS and Windows, plus a `lint` job
(`dotnet format`, `ruff`, `shellcheck`) and a check that every example policy in
`examples/` still loads through the real loader.

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

**The glob and JSONPath evaluators are hand-rolled, and that is the point.** A
policy file is configuration, and both a regex compiled from configuration and a
reflection-based JSONPath library are liabilities here — the first can backtrack
catastrophically and hang every tool call, the second breaks under Native AOT.
The glob matcher is a two-pointer scan with one backtrack point, the path
resolver walks spans without allocating, and the one place a real regex is
exposed to policy input (`matches:`) runs under a 100 ms timeout.

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
