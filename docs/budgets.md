# Budgets

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
- A call to an **unknown tool** costs nothing: no downstream server owns the
  name, so it ends at the proxy's own "unknown tool" error. It is still
  evaluated by policy and audited. The flip side is that the budget does not
  stop an agent looping on a bad name — harmless, since nothing is forwarded.
- A call that was **forwarded** is charged even if the server then failed.
  Refunding failures would let a broken tool be retried without limit.
- Refusals are **audited like any other denial**, with `rule` naming the cap
  (`session.max_cost`) rather than a policy rule.

**`session` means this process.** An stdio proxy is spawned per client session,
so the counters live in memory and start again with the next session. Over
[Streamable HTTP](streamable-http.md) there is no session to attach them to, so a
`session:` cap there is a startup error — use `daily:`.

**`daily` means one UTC day, across every session.** A daily cap that reset
whenever the client reconnected would be a limit an agent defeats by being
restarted, so daily counters live in a SQLite file:

```yaml
budgets:
  session:
    max_calls: 200
  daily:
    max_calls: 2000
    max_cost: 400
```

- The file is `~/.mcp-guardrails/budgets.db`, overridable with
  `GUARDRAILS_BUDGET_DB`. It is only created when a `daily:` cap is configured.
- **One file is one budget.** Every proxy pointed at the same file draws from
  the same day, so four parallel sessions do not get four days' worth. Give an
  agent its own file to give it a separate budget.
- **The day is UTC**, 00:00 to 24:00, on purpose: local days are 23 or 25 hours
  long twice a year, and two machines in different zones sharing a file would
  disagree about which day it is. The refusal says so.
- **Check and charge are one transaction** (`BEGIN IMMEDIATE`), so concurrent
  proxies cannot both spend the last unit.
- **A call has to fit both caps.** A call the daily cap refuses is not charged
  to the session either.
- **A broken store fails closed.** If the file cannot be opened at startup the
  proxy exits with an error. If a charge fails mid-session - including another
  proxy holding the file's write lock for more than 5 seconds - the call is
  refused as `daily.unavailable`, with the database error in the audit log's
  `decision_reason`, and is not forwarded.

The daily refusal tells the agent when the budget comes back instead of
suggesting a new session, which would not help:

```text
Blocked by guardrails budget 'daily.max_cost': this call costs 25 and 390 of
today's 400 budget is already spent (days are UTC). Stop calling tools and tell
the user the daily budget is exhausted; only they can raise
'budgets.daily.max_cost', otherwise it resets at 00:00 UTC.
```

Budgets are per machine (or per shared file), not distributed: coordinating a
budget across hosts is out of scope for v1.
