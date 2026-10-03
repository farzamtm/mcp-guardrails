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
