# Protocol compatibility

MCP is in two eras at once. The **2026-07-28** revision replaced the
`initialize` handshake with `server/discover` and per-request metadata, made
Streamable HTTP stateless, and introduced Multi Round-Trip Requests (MRTR). Every
client and server written before it still speaks the **initialize era**
(2024-11-05 through 2025-11-25). A proxy sits between the two, so it has to talk
to both — often on the same run, one era on each side.

This page says what this build actually does. It is derived from the code and
from the SDK it is built on; where something comes from SDK documentation rather
than from a test in this repository, it says so, and anything not verified is
marked **(unverified)**.

## At a glance

| | Supported today |
| --- | --- |
| SDK | [`ModelContextProtocol` 2.2.0](../src/McpGuardrails.Core/McpGuardrails.Core.csproj) |
| Protocol revisions | 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25, 2026-07-28 — the full set the SDK supports, on both sides |
| Transport to the client | stdio, or stateless Streamable HTTP with `--transport http` (no `Mcp-Session-Id`, no GET/SSE stream, so no server-to-client requests) |
| Transport to upstream servers | stdio only (spawned child processes) |
| Features proxied | Tools: `tools/list`, `tools/call` |
| Not proxied | Resources, prompts, completions, logging, subscriptions, `listChanged` notifications, progress |
| Approval mechanism | Elicitation (`elicitation/create`), form mode, held open until answered — stdio only; or a signed webhook on either transport |
| Tasks extension / MRTR approval | **Not implemented** |
| Tested end to end | Initialize handshake at 2025-06-18 with and without the elicitation capability, and a client that sends no handshake at all ([`scripts/smoke.py`](../scripts/smoke.py)) |

## Two connections, negotiated separately

The proxy does not forward the handshake, because there is nothing to forward:
it is a complete MCP server to the client and a complete MCP client to each
upstream, and each connection negotiates on its own
([`Program.cs`](../src/McpGuardrails.Cli/Program.cs),
[`UpstreamRegistry.cs`](../src/McpGuardrails.Core/Upstream/UpstreamRegistry.cs)).
That is the spec's "discovery-first, no handshake proxying" in practice, and it
is what lets a 2026-07-28 client use a 2025-06-18 server through the proxy: no
negotiated state crosses from one side to the other. Capabilities are not merged
either — the client sees the proxy's own (tools), not a union of the upstreams'.

### Client-facing: the proxy as a server

`McpServerOptions.ProtocolVersion` is left unset, which per the SDK means the
server accepts every revision it knows:

- **Initialize-era clients** get the version they asked for if it is supported,
  and 2025-11-25 otherwise.
- **2026-07-28 clients** that open with `server/discover` are offered the
  per-request-metadata revisions, which in SDK 2.2.0 is 2026-07-28 alone.
- **A client that skips the handshake** and sends `tools/call` straight away is
  served; the smoke test relies on this. It simply has no declared capabilities,
  which matters for approval (below).

The server identifies itself as `mcp-guardrails` `0.1.0` and registers only
`tools/list` and `tools/call` handlers. Upstream servers' `instructions` are not
passed on.

### Upstream-facing: the proxy as a client

Upstreams are connected with `clientOptions: null`, so the SDK defaults apply:

1. Prefer 2026-07-28 and **probe with `server/discover`**.
2. If the server answers "method not found", or says nothing within
   `DiscoverProbeTimeout` (5 s by default), **fall back to `initialize`** on the
   same connection and settle on an initialize-era version the server supports.

The official Node filesystem server is initialize-era, which is why a
`server/discover: Method not found` line appears on stderr at every start — the
fallback working as designed, not an error. A server that silently drops the
unknown method instead costs up to five seconds at startup. Upstreams connect in
parallel and before the proxy starts reading its own stdin, so the client's first
request waits for the slowest upstream.

No client handlers are registered, so the proxy offers upstreams **no sampling,
elicitation or roots**. An upstream that needs those to function will not work
through the proxy. That is also a security property — see the
[threat model](threat-model.md#what-a-downstream-server-can-still-do).

Each upstream's tool list is read once, at connect time. Tool definitions are
copied field by field under the namespaced name — name, title, description,
input and output schema, annotations, icons and `_meta`, which is every property
`Tool` has in SDK 2.2.0
([`ToolNamespacer.Qualify`](../src/McpGuardrails.Core/Upstream/ToolNamespacer.cs)).
A future SDK that adds a field will need that copy updated, or the field will be
silently dropped.

## What crosses on a call

- **Forwarded:** the tool name (de-namespaced) and the arguments, as one parsed
  dictionary — the same one policy evaluated.
- **Not forwarded:** request `_meta`, including a progress token. Progress from
  the upstream does not reach the client.
- **Returned:** the upstream's result, possibly rewritten by the
  [result scanner](result-scanning.md). An annotated result keeps
  `content` and `isError`; result-level `_meta` is not carried over. If the
  original had `structuredContent`, the annotated result does not: the payload
  is delivered as text inside the fence instead and `isError` is set, so a
  client that validates against the tool's `outputSchema` accepts it. A blocked
  result is replaced entirely.

Older clients and `structuredContent`: structured output arrived in 2025-06-18,
and a client that predates it reads `content` only. The scanner's fence goes in
`content`, so those clients see the warning — and since a flagged result's
`structuredContent` is withheld, so does every newer client. Whether the SDK strips newer
fields (`title`, `icons`, `structuredContent`, …) when an older revision was
negotiated, or sends them for the client to ignore, is **(unverified)**.

## Approval across the eras

The spec plans three approval paths: MRTR/Tasks for modern clients, out-of-band
(Slack/webhook) for headless agents, and a "hold the request" fallback for
initialize-era clients. **This build ships one: elicitation, held open.**
[`ElicitationApprovalChannel`](../src/McpGuardrails.Cli/ElicitationApprovalChannel.cs)
asks with a single required boolean field `approve`, and
[`ApprovalGate`](../src/McpGuardrails.Core/Approval/ApprovalGate.cs) owns the
deadline and turns the answer into a verdict.

The gate fails closed in every row below: no client behaviour turns
`require_approval` into an unasked `allow` except `on_timeout: allow`, which the
operator writes on purpose.

| Client | What happens | `approval` in the log | Verified |
| --- | --- | --- | --- |
| Initialize era, declares `elicitation` | Proxy sends `elicitation/create` and keeps the `tools/call` open until the human answers or `timeout_s` (default 300) passes. Explicit `approve: true` forwards the call; anything else refuses it. | `approved`, `declined`, `timed_out` | Yes — smoke test at 2025-06-18 |
| Declares no `elicitation` capability | Refused immediately with a message telling the model the client cannot ask anyone. | `unavailable` | Yes |
| Sends no handshake at all | Same as above: no capabilities, nobody to ask. | `unavailable` | Yes — smoke test |
| 2024-11-05 / 2025-03-26 | Elicitation was introduced in 2025-06-18, so a spec-conforming client on these revisions cannot declare it and lands in the row above. The proxy checks only whether the capability is present, not the version. | `unavailable` | By reading the code |
| Declares elicitation with **URL mode only** (2025-11-25) | The proxy sends a form-mode request; the SDK refuses to send form mode to a client that did not declare it and throws, and the gate turns that into a refusal. | `failed` **(unverified)** | No |
| Client gives up first (its own request timeout, or the user cancels) | The cancellation propagates; nothing is forwarded. The audit line records the error and **no decision**, because none was reached. | *(absent)* | By reading the code |
| 2026-07-28 client, over stdio | See below. | **(unverified)** | No |
| Any client, over Streamable HTTP | Stateless HTTP has no channel for a server-to-client request, so the proxy does not try: refused immediately, whatever the client declared. A `mode: webhook` rule is unaffected. | `unavailable` | Yes — smoke test |
| Tasks-capable client | Tasks are not implemented or advertised; the call is handled exactly as for its protocol revision. A task-augmented `tools/call` is **(unverified)**. | — | No |

### Why "held open" is the down-level path, and what it costs

Holding the request means the tool call stays pending for as long as the human
takes, up to `timeout_s`. That is fine over stdio, where the proxy is a
long-lived process anyway, and it is what the smoke test exercises. Its weak
point is the client's own request timeout, which may well be shorter than five
minutes — it varies by client and is **(unverified)** for any specific one. The
spec's fallback design sends progress
notifications to keep the request alive; **this build does not send any**, so a
`timeout_s` longer than the client's request timeout means the client cancels
first. Keep `timeout_s` under your client's limit, or expect cancellations
(which refuse the call — they do not forward it).

### 2026-07-28 clients (unverified)

Under 2026-07-28 the server-to-client `elicitation/create` request is replaced
by MRTR: the server returns an `input_required` result and the client retries the
call with the answers attached. What this proxy does with such a client has not
been tested, and the SDK documentation points two ways:

- The SDK's elicitation docs say the legacy `ElicitAsync` keeps working on
  **stdio** sessions under 2026-07-28, because stdio is implicitly stateful. On
  that reading the proxy sends `elicitation/create` to a client whose revision
  removed it. The SDK's own client accepts this with a warning; another client
  may not, in which case the request fails and the gate refuses the call
  (`failed`).
- The SDK's API docs also describe an MRTR wrapper that, when a handler awaits
  `ElicitAsync`, returns an `input_required` result early and resumes the handler
  on the retry. If that applies to the proxy's call-tool filter, a 2026-07-28
  client would see a native MRTR round trip without any proxy change.

There is a third possibility in front of both: the gate first checks
`ClientCapabilities.Elicitation`, and whether the SDK populates that from
2026-07-28 per-request metadata is not established. If it does not, every such
client gets `unavailable`.

Every one of those outcomes is a refusal or a real human answer; none of them is
a bypass. Pinning down which one happens, with a test, is the first piece of work
for the MRTR approval channel.

### Not yet

- **MRTR / Tasks approval** — returning `input_required` instead of holding the
  request, so approval survives client timeouts and works without a persistent
  connection. It belongs behind the existing `IApprovalChannel` seam
  ([`IApprovalChannel.cs`](../src/McpGuardrails.Core/Approval/IApprovalChannel.cs)).
  The `ModelContextProtocol.Extensions.Tasks` package the spec names is not
  referenced.
- **Slack approval** (`mode: slack`) — not a recognised mode, so rejected at
  load time today. Out-of-band approval through `mode: webhook` is implemented.
- **Streamable HTTP.** Not hosted. When it is, note that the SDK refuses
  `ElicitAsync` on stateless servers, which includes every 2026-07-28 HTTP
  request — so over HTTP the current channel would fail closed for modern
  clients, and the MRTR channel stops being optional.
- **Forwarding progress, `listChanged`, resources and prompts.**

## Sources

- The code on this branch, as linked above.
- `ModelContextProtocol.Core` 2.2.0 XML documentation for `McpClientOptions.ProtocolVersion`,
  `McpClientOptions.DiscoverProbeTimeout`, `McpServerOptions.ProtocolVersion`,
  `McpProtocolVersions`, `McpServer.ElicitAsync` and the MRTR types.
- C# SDK conceptual docs (MRTR, elicitation, stateless), retrieved through
  Context7 from `modelcontextprotocol/csharp-sdk`.
