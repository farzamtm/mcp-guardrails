# Scanning servers offline

`mcp-guardrails scan` connects to MCP servers, checks the tool definitions they
advertise, prints a report and exits. Nothing is served and nothing is proxied,
so it is a way to look at a server before putting it in any call path, or in CI
on every change to a servers file.

It runs fully offline: no API key, no account, no network access beyond
reaching the servers themselves.

```bash
# One server, straight from its command line
mcp-guardrails scan --command npx -y @modelcontextprotocol/server-filesystem@2026.8.31 /tmp/sandbox

# A remote server
mcp-guardrails scan --url https://mcp.example.com/mcp --header "Authorization: Bearer $TOKEN"

# Everything in a servers file (or the default one, when no flag is given)
mcp-guardrails scan --servers servers.yaml

# Machine-readable
mcp-guardrails scan --json --servers servers.yaml > scan.json
```

## What it checks

Every check reads only the tool definitions, never calls a tool.

| Check | Finds | How |
| --- | --- | --- |
| `injection` | Instructions aimed at the model in a tool's name, title, description, or anywhere in its input or output schema: "ignore previous instructions", role hijacks, pointers at secrets plus somewhere to send them, "don't tell the user", invisible or bidirectional Unicode | The same heuristics the proxy runs on every tool definition at startup ([result scanning](result-scanning.md#tool-definitions-too)). A tool `scan` flags is a tool the proxy would annotate or withhold. |
| `schema-suggestion` | A `default`, `const` or `examples` value in the input schema that the [argument detectors](argument-scanning.md) would flag if the model sent it: an internal or cloud-metadata URL, a credential file path, `..` traversal, shell metacharacters for a command tool | A model filling in arguments copies what the schema suggests, so a suggested `http://169.254.169.254/` is a request for that URL without the prose ever saying so. |
| `read-only-mismatch` | A tool that declares `readOnlyHint: true` while its name or description uses `delete`, `remove`, `drop`, `write`, `update`, `send` or `execute` (any inflection) | Policy rules that allow `readOnlyHint: true` trust that hint, and a server can describe its delete tool as read-only. Whole words only, so `select_dropdown` is not "drop". A description saying "does not delete anything" is still reported: a person reads this report, so recall beats precision. |

The report also lists, per tool, which behaviour hints it declares, and counts
the tools that declare none, which is the case policy rules matching on
annotations can't see into.

## Reading the report

```text
target  stdio  python3 scripts/fixture_server.py --hostile
  ! delete_record: declares readOnlyHint: true, but its name says 'delete'
  ! delete_record: declares readOnlyHint: true, but its description says 'delete'
  ! lookup: prompt-injection heuristics (instruction-override, exfiltration) in its description
  ! fetch_page: a URL pointing at an internal, loopback or cloud-metadata address suggested by its input schema properties.url.default
  5 tools, 4 findings, 2 declaring no annotations
4 findings in 3 tools.
```

The report names tools, checks, heuristics and schema locations. It never
quotes a description, schema text or suggested value. Those are written by the
server under inspection, and a report that repeats them can carry an injection
into whatever reads it next, such as a CI log an agent is asked to summarize.
Control characters in tool names are replaced with `?` so a name can't rewrite
the terminal.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Every server was scanned and nothing was found |
| 1 | Something was found, a configured server could not be reached, or the servers file is invalid |
| 2 | The command line is unusable (an unknown flag, `--command` with `--url`, ...) |

An unreachable server is never a clean result. An `optional: true` server that
is down is listed as "unavailable, not scanned" and makes the exit code 1; a
required one stops the scan with nothing scanned.

## The JSON form

`--json` prints the same report as one indented document:

```json
{
  "version": 1,
  "servers": [
    {
      "name": "target",
      "transport": "stdio",
      "source": "python3 scripts/fixture_server.py --hostile",
      "identity": "sha256:80eb...",
      "tools": [
        {
          "name": "delete_record",
          "hash": "sha256:5f1c...",
          "annotations": ["readOnlyHint=true"],
          "findings": [
            { "check": "read-only-mismatch", "names": ["delete"], "where": ["name"] }
          ]
        }
      ]
    }
  ],
  "unavailable": [],
  "tool_count": 5,
  "finding_count": 4,
  "clean": false
}
```

| Field | Meaning |
| --- | --- |
| `source` | How the server was started or reached, as written before `${VAR}` expansion, so a token reference is shown but never its value. Absent for the built-in server. |
| `identity` | The fingerprint [pinning](pins.md) keys the server on: the command and arguments, or the URL. |
| `hash` | The tool's hash in exactly the canonical form the pins file uses, so a scan can be compared with a pins file, and two scans of the same server show which definitions changed between releases. |
| `annotations` | The behaviour hints the tool declares, with their values. Empty means none. |
| `findings[].names` | Heuristic names, a detector name, or the verb that suggested a write. Always from the proxy's own vocabulary. |
| `findings[].where` | The part of the definition: `description`, `input schema`, `input schema properties.url.default`, `name`, ... |

`version` changes if a field changes meaning.

## Targets and their environment

- **`--command <program> [args...]`** takes the rest of the command line, so the
  server's own flags are never read as `scan`'s. Put `scan`'s own flags before
  it. The target is started with an **isolated environment**: the built-in
  allowlist (`PATH`, `HOME` and the like) and nothing else from your shell. A
  server you're scanning is one you haven't decided to trust yet, and the shell
  you scan from probably holds API keys. A server that needs a token to start
  belongs in a servers file, where the token is passed explicitly.
- **`--url <url>`** scans a Streamable HTTP server, or an SSE one with `--sse`.
  `--header "Name: value"` adds a static header and can be repeated. The URL must
  be https unless the host is loopback.
- **No target flag** scans the servers the proxy would serve: `--servers`, then
  `GUARDRAILS_SERVERS`, then `~/.mcp-guardrails/servers.yaml`, then the built-in
  filesystem server.

Both target flags go through the same rules as a servers file: the command has
to resolve, an unpinned `npx -y pkg` or `uvx pkg` is warned about, and a `$`
on the command line is kept literally rather than read as a `${VAR}` reference,
since the shell has already expanded what it was going to.

## What `scan` leaves alone

`scan` reads no policy, writes no audit log, and neither reads nor writes the
pins file. Its result depends only on what the servers advertise, so the same
servers give the same report on every machine, whatever a local policy happens
to switch off. To check servers against their pins, use
[`pins status`](pins.md).

## Limits

- Heuristics, not a verdict. A clean report means none of these patterns
  matched, not that a server is safe. A server can behave differently once
  called, or serve different definitions to different clients.
- Only `tools/list` is read. Resources and prompts are not.
- The read-only check looks at English verbs.
- A server that doesn't start without credentials needs a servers file entry
  that passes them, and a remote server behind OAuth can't be scanned until the
  proxy supports OAuth to upstreams.
