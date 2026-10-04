# Policy

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
[`examples/filesystem-sandbox.yaml`](../examples/filesystem-sandbox.yaml).

## What a rule can match on

Four kinds of condition, combined with AND. An omitted condition is skipped, so
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

**Server globs** match the name of the server that owns the tool, as named in
the [servers file](servers.md): `server: github` says what `tool: github__*`
says, but keeps reading as what it means when the rule also narrows by
annotations or arguments. A call to a tool no server advertises has no server,
so a `server:` condition never matches it. `validate` warns about a rule whose
`server:` matches no configured server, because a rule that can never match is
a guardrail that is not there.

```yaml
rules:
  - name: approve-github-writes
    match:
      server: github
      annotations: { readOnlyHint: false }
    decision: require_approval
```

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

A value that *is* sent but is not a string — an array, number, object, boolean
or `null` — **satisfies `not_prefix`**, because it cannot be shown to start
with the prefix. That keeps a deny rule such as `not_prefix: /workspace/`
firing on `{"path": ["/etc/passwd"]}`, which a downstream server might well
accept. The flip side: do not write an allow rule with `not_prefix`, since it
would allow those values too. Allow with `prefix`, which only a matching string
satisfies, and deny with `not_prefix`.

`eq` and `in` compare numbers by value and exactly: `1`, `1.0` and `1e0` are
equal, while `9007199254740993` and `9007199254740992` are not, however far
past double precision they sit.

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

## Starting from a pack

You do not have to begin with a blank file. `mcp-guardrails init` writes a
policy from the built-in [policy packs](packs.md), one per popular server, with
every rule commented. The generated file is yours to edit.

## Testing a policy

A policy is code, so it can have tests. A test file names the policy, the tools
it is tested against, and calls with the decision each should get:

```yaml
# policy.test.yaml
policy: policy.yaml                 # relative to this file
tools:                              # what the servers advertise, with their hints
  fs__read_text_file: { readOnlyHint: true }
  fs__write_file: {}
cases:
  - call: fs__read_text_file
    args: { path: /workspace/README.md }
    expect: allow
  - name: writes outside the workspace are refused
    call: fs__write_file
    args: { path: /etc/hosts }
    expect: deny
    rule: keep-writes-in-workspace  # optional: which rule should decide it
```

```bash
mcp-guardrails policy test policy.test.yaml
```

Each case runs through the proxy's real policy evaluator, with the facts the
proxy would build for that call: an advertised tool has its server (the part of
the name before `__`) and its hints. No server is spawned, so it runs in CI with
no network or keys. A failing case prints the full decision trail, the same text
`--explain` adds to a refusal. The exit code is 1 when anything fails.

The policy's secret blocking (`scanners.secrets.arguments: block`) and then its
[argument detectors](argument-scanning.md) run after the rules, as they do in
the proxy, so a refusal under `secrets.arguments` and a `block` or `approve`
from `scanners.arguments` show up in `expect:` and `rule:` (`arguments.ssrf`,
say). `argument_hits: [ssrf]`
asserts which detectors fire, in any order, and `argument_hits: []` that none
do. That is the only way to test them under the default `audit`, which never
changes the verdict. Budgets, result scanners and approval act on a running
session and are not part of a test.

A few rules keep a test from silently testing nothing:

- **Unknown keys are errors**, at every level. A misspelt `expected:` would
  otherwise leave a case asserting nothing.
- **Every `call:` must be listed under `tools:`**, so a typo in a tool name
  fails instead of quietly becoming a call to an unknown tool. To test what
  happens to a tool no server advertises, say so with `unknown: true`; that call
  has no server and no hints, as in the proxy.
- An entry under `tools:` with no hints (`fs__write_file: {}`) declares none,
  and the MCP defaults apply: not read-only, destructive.

`policy:` may also name a pack file, with `server:` giving the name to fill in.
That is how the shipped packs are tested.

Only the policy decision is tested. Budgets, scanners and approval act on a live
session; the smoke test covers those.
