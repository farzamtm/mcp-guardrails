# Approval

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
downstream or comes back refused. Under the prompt — the rule's own or the
generated one — the client also shows the arguments, because "allow
`fs__write_file`?" is not a question anyone can answer without the path:

```text
Allow the agent to call 'fs__write_file'? Guardrails rule 'approve-writes' requires your approval.

Arguments (as sent by the agent; secrets redacted, long values cut):
{"path": "/srv/app/.env", "content": "DEBUG=1\nAWS_KEY=[REDACTED:aws-access-key]\n"}
```

When the [argument detectors](argument-scanning.md) flagged the call, a sentence
saying what they found and in which argument is appended to the prompt, so the
warning reaches the human however the rule worded its question. Under
`scanners.arguments.action: approve` a call no rule sent to a human is asked
about too, under the rule `arguments.<detector>`.

The arguments are summarised exactly as for a [webhook](#asking-a-webhook-instead) —
secrets redacted, then each value cut at 256 characters — and written as one
line of JSON, so line breaks or a fake "approved by guardrails" inside an
argument stay escaped inside a quoted string rather than passing for the
proxy's own text. Invisible formatting characters (bidi overrides, zero-width
spaces) are shown as `\uXXXX` escapes. The line stops at 2,048 characters and
says how many arguments it left out. Nothing is forwarded while the question is
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

**Over Streamable HTTP, in-band approval is always `unavailable`.** Elicitation is a
request from the server back to the client, and stateless HTTP has no channel to
send it on — the SDK disables it outright. So under `--transport http` every
`require_approval` call is refused immediately, with a message that says why;
it never hangs until the deadline and it never falls through to `allow`. For
rules that need a human, use `mode: webhook` (below), which does not go through
the client, or stdio, until the Tasks/MRTR channel lands. `mode: local_ui` will
be a second option once the local dashboard ships.

## Asking a webhook instead

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
needs to see *which* path, not the 40 KB being written to it. Secrets the
[redaction detectors](secret-redaction.md) recognise are replaced with markers
first, whatever `scanners.secrets` says; emails and card numbers are not, since
"which customer" is often the question. Everything else is exactly what the
model sent, so run the endpoint somewhere you would be comfortable storing it.

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

See [`examples/webhook-approval.yaml`](../examples/webhook-approval.yaml), and
`scripts/smoke.py` for a 40-line receiver that verifies the signature.

## Asking the local UI instead

> **Not usable yet.** The proxy side of this mode is in place, but the local
> dashboard that answers it - `mcp-guardrails ui` - has not shipped. Until it
> does, nothing writes the rendezvous file described below, so every
> `mode: local_ui` call is refused, the same way it would be with the UI
> stopped. It is documented now so the contract is reviewable before the
> dashboard is built on it.

A webhook needs an endpoint you build and host. For an autonomous agent or a
stateless-HTTP deployment on your own machine, `mcp-guardrails ui` will give you
an approval inbox with nothing to stand up:

```yaml
rules:
  - name: approve-deletes
    match:
      tool: "*__delete_*"
    decision: require_approval
    approval:
      mode: local_ui
```

There is no `approvers:` section to write — unlike a webhook, the UI is not a
URL you configure, it is a process found at runtime. When `mcp-guardrails ui`
is running, it writes its loopback address and a fresh per-run secret to
`~/.mcp-guardrails/ui.json` (override with `GUARDRAILS_UI_FILE`). Every proxy
that needs to ask reads that file afresh, so the UI can be started after the
proxy, or stopped and restarted while it keeps running.

**The wire protocol is the webhook's**, pointed at the UI instead of a
configured endpoint: the same signed POST, the same `{"request_id",
"decision"}` reply, the same redaction, correlation check and fail-closed
rules. A missing or unparsable rendezvous file — or one naming anything other
than plain `http://` to a literal loopback address — means no UI, and the call
is refused with a message telling the model to have the user run
`mcp-guardrails ui` and try again. It is never a fallback to asking the
client: a rule routed to the local UI because the client cannot ask, or the
transport is stateless HTTP, so there is nothing to fall back to.

The audit log's `approval_channel` field records which channel answered —
`in_band`, `webhook` or `local_ui` — alongside `approval`, because "approved"
means something different depending on who was asked.

See [`examples/local-ui-approval.yaml`](../examples/local-ui-approval.yaml).

**Not implemented yet:** Slack approval is planned. Until it exists, `slack` is
not a recognised `mode`, so `mode: slack` fails at load time like any other
unknown value rather than being silently ignored: accepting configuration the
proxy does not honour would show the operator a safeguard that does nothing.
The Tasks/MRTR path — returning an `input_required` task instead of holding the
request open — lands behind the same `IApprovalChannel` seam.
