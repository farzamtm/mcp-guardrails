# The audit log

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

Each downstream server is recorded once at startup, when serving begins, with
what it was launched from. `identity` is the command line or URL as written in
the [servers file](servers.md), with `${VAR}` references unexpanded and
anything secret-shaped masked; `tool` is absent because the line is about a
server:

```json
{"ts":"2026-10-04T10:00:00.120000+00:00","event":"upstream_connected","server":"github",
 "transport":"stdio","tool_count":26,
 "identity":"docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN ghcr.io/github/github-mcp-server",
 "duration_ms":0,"is_error":false}
```

`transport` is `stdio`, `http` or `sse`.

```bash
# Which servers did each session talk to?
jq -r 'select(.event == "upstream_connected") | [.ts, .server, .transport, .identity] | @tsv' ~/.mcp-guardrails/audit.jsonl
```

A call whose result matched a scanner carries two more fields. Their absence on a
forwarded call means the result was clean; their absence on a refused call means
nothing came back to scan. A third, `scanner_structured_content_withheld`, is
`true` when the server returned `structuredContent` and the client did not get
it — which is also why `is_error` below is `true` on a read that succeeded.

```json
{"ts":"2026-09-20T18:41:02.113847+00:00","event":"tool_call","tool":"fs__read_text_file",
 "server":"fs","downstream_tool":"read_text_file","decision":"allow",
 "scanner_hits":["instruction-override","exfiltration"],"scanner_action":"annotated",
 "scanner_structured_content_withheld":true,"duration_ms":3.21,"is_error":true}
```

A tool whose definition matched is recorded once, at startup, as its own event
with the same two fields:

```json
{"ts":"2026-10-02T09:12:44.501233+00:00","event":"tool_metadata","tool":"fs__read_note",
 "server":"fs","downstream_tool":"read_note",
 "scanner_hits":["instruction-override"],"scanner_action":"blocked",
 "duration_ms":0,"is_error":false}
```

[Pinning](pins.md) writes its own events at startup and from the `pins`
commands: `pin_created` when a server is pinned on first use, `pin_changed`
for each tool that differs from its pin, `pin_removed` for each pinned tool
that is gone, and `pin_accepted` / `pin_reset` when someone reviews a change.
`pin_change` says why a tool differs (`changed`, `added` or `identity_changed`)
and `scanner_action` what was done about it:

```json
{"ts":"2026-10-04T10:00:00.130000+00:00","event":"pin_changed","tool":"github__create_issue",
 "server":"github","downstream_tool":"create_issue","pin_change":"changed",
 "scanner_action":"blocked","duration_ms":0,"is_error":false}
```

```bash
# Which tools changed since they were pinned, and what was done about it?
jq -r 'select(.event == "pin_changed") | [.ts, .tool, .pin_change, .scanner_action] | @tsv' ~/.mcp-guardrails/audit.jsonl

# What was accepted, and when?
jq -r 'select(.event == "pin_accepted") | [.ts, .tool] | @tsv' ~/.mcp-guardrails/audit.jsonl
```

These are names and verdicts only, never the text of a definition.

A call that carried or returned a secret says which detectors fired and what
was done, and its `arguments` hold markers rather than the values:

```json
{"ts":"2026-10-01T09:12:44.501270+00:00","event":"tool_call","tool":"fs__write_file",
 "server":"fs","downstream_tool":"write_file","decision":"allow",
 "arguments":{"path":"/tmp/guardrails-sandbox/.env","content":"KEY=[REDACTED:aws-access-key]"},
 "argument_secrets":["aws-access-key"],"argument_secrets_action":"forwarded",
 "duration_ms":4.02,"is_error":false}
```

`forwarded` is the value to search for: the key is out of the log, but it did
reach the server. The others are `redacted` and `blocked`; results use
`result_secrets` and `result_secrets_action` (`redacted` or `blocked`).

When the classifier ran, there are up to three more fields:

- `classifier`: `benign`, `injection`, `timed_out` or `failed`
- `classifier_truncated`: `true` only when the result was cut down to `max_chars`
- `classifier_error`: on failure, a short reason such as an HTTP status

As with `scanner_hits`, these record the verdict and never the text.

```bash
# Calls where the heuristics and the classifier disagreed
jq 'select(.scanner_hits and .classifier == "benign")' ~/.mcp-guardrails/audit.jsonl

# Is the classifier actually working?
jq -r 'select(.classifier) | .classifier' ~/.mcp-guardrails/audit.jsonl | sort | uniq -c
```

```bash
# What did my agent touch, and how long did it take?
jq -r '[.ts, .tool, (.duration_ms|tostring)] | @tsv' ~/.mcp-guardrails/audit.jsonl

# Only the failures
jq 'select(.is_error)' ~/.mcp-guardrails/audit.jsonl
```
