# OpenTelemetry

The JSONL log answers "what happened in this session". OpenTelemetry answers it
across many sessions, on the dashboards you already have. Export is **off by
default** and switched on by either:

- setting `OTEL_EXPORTER_OTLP_ENDPOINT` (the standard OTel variable), or
- passing `--otel`, which exports to the default collector on `localhost:4317`.

All the standard `OTEL_*` variables apply: `OTEL_EXPORTER_OTLP_PROTOCOL`,
`OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_SDK_DISABLED`, and so on.

## Quickstart: the Aspire dashboard

The [Aspire dashboard](https://aspire.dev/dashboard/standalone/) is a single
container that shows traces and metrics:

```bash
docker run --rm -d --name aspire-dashboard \
  -p 18888:18888 -p 4317:18889 \
  -e ASPIRE_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS=true \
  mcr.microsoft.com/dotnet/aspire-dashboard:latest

OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 \
  ./src/McpGuardrails.Cli/bin/Debug/net10.0/McpGuardrails.Cli
```

Open <http://localhost:18888> and the `mcp-guardrails` service appears after its
first tool call. (`UNSECURED_ALLOW_ANONYMOUS` skips the login token. That is fine
on a laptop, not on a shared host.)

From Claude Desktop, put the variable in the server's `env` block next to
`GUARDRAILS_POLICY`.

[Jaeger](https://www.jaegertracing.io/) works the same way for traces, though it
has nowhere to put metrics:

```bash
docker run --rm -d --name jaeger -p 16686:16686 -p 4317:4317 jaegertracing/jaeger:latest
```

## What is exported

One trace per tool call shows the whole hop. The MCP SDK's own `tools/call`
server span is the root; the guardrails span, `guardrails tools/call <tool>`,
sits inside it; the SDK's client span for the downstream call sits inside that.
A call that policy refused has no client span, which is how you can see that
it never left the proxy.

| Attribute | Meaning |
| --- | --- |
| `gen_ai.tool.name` | Client-visible tool name (semconv) |
| `mcp_guardrails.server`, `mcp_guardrails.downstream_tool` | Where the call was routed |
| `mcp_guardrails.decision` | `allow`, `deny`, `require_approval`, as in the audit log |
| `mcp_guardrails.decision.source` | `policy`, `budget`, `approval` or `scanner` |
| `mcp_guardrails.rule` | Rule that decided, or the budget limit (`session.max_cost`) |
| `mcp_guardrails.budget.cost` | What the call costs against the budget |
| `mcp_guardrails.approval.outcome` | `approved`, `declined`, `timed_out`, `unavailable`, `failed` |
| `error.type` | Exception type, or `tool_error` when the downstream tool reported failure (semconv) |

| Metric | Type | Attributes |
| --- | --- | --- |
| `mcp_guardrails.tool_calls` | counter | tool, server, decision, `error.type` |
| `mcp_guardrails.denials` | counter | tool, server, decision source, rule |
| `mcp_guardrails.approvals` | counter | tool, server, rule, approval outcome |
| `mcp_guardrails.tool_call.duration` | histogram, seconds | tool, server, decision, `error.type` |

The SDK's semconv metrics (`mcp.server.operation.duration`,
`mcp.client.operation.duration`, ...) are exported alongside these.

Telemetry is held to a **stricter** privacy line than the audit log. A trace
backend is usually shared far more widely than a file on the proxy's own disk,
so:

- **argument values are never exported**, and neither are exception messages or
  decision reasons, which can quote arguments. A span carries the exception
  *type* and the rule *name*, which is enough to find the full audit line.
- a tool name the proxy could not resolve is free text from the client, so
  metrics record it as `_OTHER` rather than minting a time series per typo.
- **a denial is not an error.** The model receives it as an `isError` result,
  but the span status stays unset: a denial is the guardrail working, and
  counting it as a failure would turn every error-rate panel into a denial-rate
  panel.

`scripts/smoke.py` runs a session against a fake OTLP collector and checks that
spans and metrics arrive and that an argument value sent in the call appears
nowhere in what was exported.
