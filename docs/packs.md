# Policy packs

A blank policy file is a hard place to start: which rules matter for the GitHub
server, or for a database? The proxy ships a **pack** for each popular server,
and `init` turns the ones you need into a single policy file.

| Pack | For | Reads | Changes | Refused outright |
| --- | --- | --- | --- | --- |
| `filesystem` | [official filesystem server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) | allowed | need approval | credential files (`.ssh`, `.aws`, `.env`, keys…); git hooks, CI workflows, shell startup files and editor or agent settings; `read_multiple_files` |
| `github` | [GitHub MCP server](https://github.com/github/github-mcp-server) | allowed | need approval | secret-scanning alerts; changing rulesets and custom properties |
| `git` | [`mcp-server-git`](https://github.com/modelcontextprotocol/servers/tree/main/src/git) | allowed | need approval | refs starting with `-`, which git would read as options |
| `postgres` | Postgres servers with a `sql` argument | single `SELECT`-style statements allowed | writes need approval | several statements in one call; server file access, `COPY`, `dblink`, ending other sessions |
| `fetch` | [`mcp-server-fetch`](https://github.com/modelcontextprotocol/servers/tree/main/src/fetch) | public http(s) URLs allowed | — | non-web schemes; localhost, private networks, link-local and cloud metadata addresses |
| `playwright` | [Playwright MCP](https://github.com/microsoft/playwright-mcp) | browsing and interacting allowed | `browser_evaluate` and file uploads need approval | `browser_run_code_unsafe`; `file:`, `chrome:`, `javascript:` and similar URLs |
| `supabase` | [Supabase MCP server](https://github.com/supabase-community/supabase-mcp) | allowed, plus read-only `execute_sql` | migrations, deployments, branch and project changes, SQL writes need approval | server file access, `COPY`, `dblink`, ending other sessions |

`mcp-guardrails init --list` prints the same list with what each pack
recognizes. The packs live in [`packs/`](../packs/), one YAML file each, and
each starts with a comment saying what it protects, what it allows, and the
threat it addresses.

## Generating a policy

```bash
mcp-guardrails init                          # a pack for every server init recognizes
mcp-guardrails init --pack github            # this pack, for every server it recognizes
mcp-guardrails init --pack github=gh         # this pack, for the server named gh
mcp-guardrails init --pack filesystem --pack github -o policy.yaml
```

- **Recognition.** `init` reads your [servers file](servers.md) (or, with
  none, the built-in filesystem server) and matches each server's command line
  or URL against what the packs recognize: package names such as
  `@modelcontextprotocol/server-filesystem`, image names such as
  `ghcr.io/github/github-mcp-server`, and URLs such as
  `https://api.githubcopilot.com/mcp`. Names match whole, with versions
  stripped, so `mcp-server-git` never claims `mcp-server-gitlab`. Matching uses
  the file as written, before `${VAR}` expansion, so no secret is read.
- **Naming.** A pack is written against a placeholder, and `init` fills in your
  server's name. Rules get the name too: the github pack applied to a server
  called `gh` produces `gh-reads`, `gh-approve-writes` and so on, so the audit
  log says which server a rule was for.
- **Output.** `-o <path>` chooses the file; the default is the policy path the
  proxy reads (`GUARDRAILS_POLICY`, else `~/.mcp-guardrails/policy.yaml`), and
  `-o -` prints it. Messages go to stderr.
- **Re-running.** The output has no date or machine name in it, so running
  `init` again with the same packs changes nothing. If the file exists and
  differs, because you edited it or a pack changed, `init` prints the diff and
  stops; `--force` replaces it.

`init` refuses rather than guessing when something is off: an unknown pack, a
pack that recognizes none of your servers and was given no name, two packs for
the same server, or a servers file with errors. Naming a server that is not
configured is only a warning, since writing the policy first is a reasonable
order to do things in; `validate` repeats the warning until the server exists.

## Why a generated file, not an include

Rules are first-match-wins, so their order is the meaning of a policy. A
runtime `include:` would hide that order across several files, and an updated
pack would change what the proxy does on its next restart with nothing in your
repository changing. A generated file keeps every rule in one place where you
can read and diff it. A newer pack only takes effect when you run `init` again
and accept the difference.

Packs can be combined in any order because every rule in a pack is scoped with
`server:` to its own server, so one pack's rules cannot match another server's
tools. Calls to servers no pack covers match nothing and are allowed and
audited; the generated file ends with a commented-out catch-all to refuse them
instead.

## What packs are, and are not

Packs are opinionated starting points, not guarantees.

- **They lean on the server's annotations.** "Reads allowed" means "tools that
  declare `readOnlyHint: true`". Those are hints from the server, and a hostile
  server can mislabel a tool. The packs name the tools that matter explicitly
  and keep the annotation rule as the net underneath.
- **Some rules are heuristics over text.** The SQL rules look for keywords, and
  lean towards asking: a column called `comment` or a string containing
  `update` needs approval. The fetch rules match host names as written, so a
  public name that resolves to a private address, or an IP in decimal, gets
  through. Each pack's header comment lists its known gaps.
- **Arrays are not inspected element by element.** That is why the filesystem
  pack refuses `read_multiple_files` outright rather than checking only its
  first path.

See the [threat model](threat-model.md) for what the proxy as a whole does and
does not defend against.

## Testing packs, and your own policy

Every pack has a test file next to it (`packs/github.test.yaml`), run by CI with
the [`policy test`](policy.md#testing-a-policy) command:

```bash
mcp-guardrails policy test packs/*.test.yaml
```

Write the same kind of file for your own policy: it is the cheapest way to know
that an edit did what you meant.

## Writing a pack

A pack file has three parts, in this order:

```yaml
# Pack: example - what it protects, what it allows, and the threat it
# addresses. This comment is copied into every policy generated from it.
pack:
  name: example                      # letters, digits and hyphens
  version: 1                         # bump when the rules change meaning
  description: One line for init --list.
  recognizes: [example-mcp-server, https://mcp.example.com/mcp]

rules:
  - name: "{{server}}-reads"
    match: { server: "{{server}}", annotations: { readOnlyHint: true } }
    decision: allow
  - name: "{{server}}-approve-rest"
    match: { server: "{{server}}" }
    decision: require_approval
```

The loader enforces the shape, because `init` copies the rules into your policy
as text, comments included:

- The header comment is required.
- `rules:` is the last section, with every line under it indented. Budgets,
  scanners and approvers are deployment choices and do not belong in a pack.
- Every rule has `server: "{{server}}"` and `{{server}}` in its name.
- A pack loads as a policy once the placeholder is filled in.

Add a `<name>.test.yaml` with cases for every rule; CI fails without one.
