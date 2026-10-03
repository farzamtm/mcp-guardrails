# Secret redaction

A credential can leak in two directions, and the proxy sits on both.

**Coming back**, a tool result is read by the model, which means it has been
sent to the model provider, may be quoted back to the user, and can be passed
to the next tool call. An agent asked to "fix the deploy script" reads `.env`
along the way, and the production key is now in a transcript.

**Going out**, the arguments the model writes reach a server — possibly a
third-party one — and the audit log. An audit log that records API keys is a
liability rather than a safety feature.

```yaml
scanners:
  secrets:
    arguments: redact_audit   # redact_audit (default) | redact | block | off
    results: redact           # redact (default) | block | off
    pii: false                # also emails and card numbers (default false)
```

**On by default, with no policy file**, for the same lopsided-costs reason as
injection scanning: a key the model has read cannot be unread, and a false
positive costs a marker where a token-shaped string used to be.

| `arguments:` | The server receives | The audit log records |
| --- | --- | --- |
| `redact_audit` | the real value | a marker |
| `redact` | a marker | a marker |
| `block` | nothing — the call is refused | a marker, and the refusal |
| `off` | the real value | the real value |

The default forwards the real value deliberately. The model may have been asked
to write that config file, and a proxy that silently rewrites it into
`aws_access_key_id = [REDACTED:aws-access-key]` breaks the task without saying
so. `redact` is for servers you do not trust with credentials; `block` refuses
the call before approval and budget run, so nobody is asked to approve a call
that carries a key they cannot see, and nothing is charged for it.

What the model sees after `results: redact`:

```text
[default]
aws_access_key_id = [REDACTED:aws-access-key]
region = eu-west-1

[guardrails] 1 sensitive value was redacted from the output of 'fs__read_text_file'
(aws-access-key) and replaced with [REDACTED:<kind>] markers. The markers are
placeholders, not the real values: do not write them back into a file...
```

Markers rather than deletions, so the model can tell a value was there and say
so. The trailing notice is the part that matters: the failure to guard against
is not the model seeing a marker, it is the model reading a config file,
editing one line, and writing the whole file back — markers included — over the
real keys. `results: block` withholds the result entirely instead.

## What it looks for

| Detector | Matches |
| --- | --- |
| `private-key` | PEM `-----BEGIN … PRIVATE KEY-----` blocks, including truncated ones |
| `jwt` | three base64url segments, the first two starting `eyJ` |
| `aws-access-key` | `AKIA`, `ASIA`, `ABIA`, `ACCA` followed by 16 characters |
| `github-token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_` |
| `slack-token`, `slack-webhook` | `xox[abposr]-…`, `https://hooks.slack.com/services/…` |
| `stripe-key` | `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_` (not publishable `pk_`) |
| `anthropic-key`, `openai-key`, `google-api-key` | `sk-ant-…`, `sk-…`/`sk-proj-…`, `AIza…` |
| `bearer-token` | the token after `Bearer` — the scheme stays readable |
| `credential-assignment` | the value in `password=…`, `api_key: "…"`, `DB_PASSWORD=…`, `"secret": "…"` |
| `sensitive-field` | the whole value of a JSON key named `password`, `client_secret`, `authorization`, `cookie`… |
| `email` | with `pii: true` |
| `credit-card` | with `pii: true`; a known network prefix **and** a valid Luhn check digit |

Prefixed tokens are matched on shape alone, because the prefix is distinctive.
The generic patterns need corroboration: an assignment's bare value must look
generated (a digit or symbol in it) and must not be code — `password =
get_password()` and `api_key = os.environ["KEY"]` are left alone, because a
marker in the middle of a source file the agent is editing would be written back
on the next save. A JSON key named just `token` is **not** treated as sensitive:
pagination cursors are called that too, and redacting one breaks the next page.

Only string values are rewritten; keys, numbers and the structure of a JSON
payload are left as they are.

**Regular expressions, but never backtracking ones.** Unlike the injection
scanner these are shapes, not phrases, and a regex is the honest way to write
`AKIA` followed by sixteen characters. Every pattern is compiled with
`RegexOptions.NonBacktracking`, which runs in time linear in the input, so no
tool result — however large or crafted — can stall the proxy. That engine has no
lookarounds or backreferences, so the context checks that would need them live
in ordinary code beside each pattern.

The audit log records which detectors fired and what became of the value —
never the value. Shapes that are not on the list — a human-chosen password
outside a recognisable assignment, a key format this proxy has not heard of —
are not caught. This narrows what leaks; it does not make leaking impossible.

```bash
# Which calls carried a credential to a server?
jq 'select(.argument_secrets_action == "forwarded")' ~/.mcp-guardrails/audit.jsonl

# Which results had something taken out?
jq 'select(.result_secrets)' ~/.mcp-guardrails/audit.jsonl
```
