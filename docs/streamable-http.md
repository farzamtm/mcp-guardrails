# Streamable HTTP

stdio is the default. To serve over HTTP instead:

```bash
McpGuardrails.Cli --transport http                # http://127.0.0.1:7300/mcp
McpGuardrails.Cli --transport http --port 0       # any free port; logged on start
```

The endpoint is `/mcp`, stateless (no `Mcp-Session-Id`, no GET/SSE stream). It
is the same server as over stdio — one registration of the handlers and every
filter, with only the listener swapped — so audit, policy, budget and approval
apply identically, with two differences worth knowing:

- **Approval cannot ask anyone** (see [Approval](approval.md)): it fails closed.
- **`budgets.session` is refused.** Stateless HTTP has no session, so a session
  cap could only be one pool shared by every client for the life of the
  process — not the limit it says it is. The proxy will not start with one; cap
  HTTP with `budgets.daily` (persisted, and process-wide by design: every proxy
  pointed at the same `GUARDRAILS_BUDGET_DB` shares it), with
  `budgets.principal` under [OAuth](oauth.md) (one cap per caller), or serve
  over stdio. Per-rule `cost:` works with a daily cap alone.

**Without [OAuth](oauth.md) there is no user authentication. Do not expose it.**
Out of the box it binds `127.0.0.1` only, and anything that can reach the port
can call every downstream tool the policy allows. Four defences are built in:

| | |
| --- | --- |
| Loopback by default | `--bind <ip>` is the only way to listen elsewhere, and a non-loopback address is **refused** unless a token is set |
| Bearer token | `GUARDRAILS_HTTP_TOKEN` (env var, not a flag, so it stays out of `ps`); at least 16 characters; compared in constant time. Clients send `Authorization: Bearer <token>` |
| OAuth access tokens | `access.oauth` in the policy: JWTs from your authorization server, validated per request, with a per-caller principal for policy, budgets and the audit log. Replaces the shared token; see [OAuth](oauth.md) |
| Origin check | A request carrying a non-loopback `Origin` is refused with 403. A loopback bind does not stop a malicious web page from making your browser POST to it (DNS rebinding); this does. Non-browser clients send no `Origin` and are unaffected |

```bash
export GUARDRAILS_HTTP_TOKEN="$(openssl rand -hex 32)"
McpGuardrails.Cli --transport http --bind 0.0.0.0 --port 7300   # still: put TLS in front
```

Bad combinations are startup errors (exit code 2), not guesses: `--port` without
`--transport http`, a repeated flag, a host name instead of an IP, a token that is
set but too short, a policy with `budgets.session` under `--transport http`, a
policy with `access.oauth` over stdio or together with `GUARDRAILS_HTTP_TOKEN`.
