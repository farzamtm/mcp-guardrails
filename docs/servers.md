# The servers file

The policy file says what calls may do. The servers file says where they go: the
downstream MCP servers the proxy connects to and fronts.

```bash
mcp-guardrails --servers ~/.mcp-guardrails/servers.yaml   # or GUARDRAILS_SERVERS
```

Where the proxy looks, in order:

1. `--servers <path>`
2. `GUARDRAILS_SERVERS`
3. `~/.mcp-guardrails/servers.yaml`

A file named by the flag or the variable **must exist**. A missing file there
is an error, not a quiet fallback to some other set of tools. If no file is
named and none exists at the default path, the proxy uses its built-in
filesystem server, so launcher configs written before the servers file existed
keep working. Setting `GUARDRAILS_SERVERS` to an empty value asks for the
built-in server explicitly and ignores the default path.

## The fastest way in: `wrap`

```bash
mcp-guardrails wrap --client claude-desktop --dry-run   # show what would change
mcp-guardrails wrap --client claude-desktop             # do it
# restart Claude Desktop
mcp-guardrails unwrap --client claude-desktop           # put everything back
```

`wrap` reads the client's server list and writes it to
`~/.mcp-guardrails/servers.yaml` (choose another path with `-o`). It then backs
up the client config and replaces its server list with a single `guardrails`
entry that launches the proxy. You get every server you had, namespaced
(`github__create_issue`), behind one policy and one audit log.

- **The backup is written and flushed to disk first.** It sits next to the
  config as `<file>.guardrails-backup-<timestamp>` and holds the original bytes
  exactly. The config itself is replaced atomically, by writing a temporary file
  and renaming it over the old one.
- **`unwrap` restores the original byte for byte.** It refuses if the config
  changed after `wrap` (a server added in the client's UI, say), because
  restoring would throw that change away. `--force` restores anyway.
- **Nothing happens if the imported servers would not start.** `wrap` validates
  the new servers file first, for example that every `command` is on PATH, and
  leaves the client config untouched if anything is wrong.
- **Secrets stay out of the servers file.** See [Import](#import) below. The
  values move into the `guardrails` entry's `env` in the client config, which is
  where they already were.

Supported clients and where their configs are read from (most specific first):

| `--client` | Files | Key |
|---|---|---|
| `claude-desktop` | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows `%APPDATA%\Claude\claude_desktop_config.json` | `mcpServers` |
| `claude-code` | `./.mcp.json`, then `~/.claude.json` (import only) | `mcpServers` |
| `cursor` | `./.cursor/mcp.json`, then `~/.cursor/mcp.json` | `mcpServers` |
| `vscode` | `./.vscode/mcp.json`, then the user profile's `mcp.json` | `servers` |

`--path` names any other file. `~/.claude.json` can be imported but not
wrapped: it is Claude Code's whole state file, and Claude Code rewrites it
constantly, so a backup of it could never be restored safely. Wrap a project's
`.mcp.json` instead.

## Import

```bash
mcp-guardrails import --from cursor -o servers.yaml
```

Turns a client's server list into a servers file, printed to stdout or written
to `-o` (it never overwrites an existing file). Along the way it:

- **lifts secrets out of the file.** A value that looks like a credential,
  either by its shape or by a name such as `GITHUB_TOKEN`, `X-Api-Key` or
  `Authorization`, becomes a `${SERVER_KEY}` reference. The real values are
  printed to stderr once, for you to put in the proxy's environment. They are
  never written to disk. Values that already reference a variable are left as
  they are.
- **renames servers whose names won't namespace.** Only letters, digits and
  hyphens are allowed, because `__` separates server from tool. `my_server`
  becomes `my-server`, and each rename is reported.
- **translates client variables:** `${workspaceFolder}`, `${userHome}`,
  `${pathSeparator}` and `${/}` are resolved. A VS Code `${input:id}` becomes
  `${ID}`, which you set yourself.
- **warns about unpinned package runners,** such as `npx -y some-server` or
  `uvx some-server` without a version.

## Format

YAML or JSON. A client config pasted in as it is usually loads.

```yaml
version: 1

defaults:
  shutdown_timeout: 5s          # per-server override allowed
  env_isolation: true           # see below
  env_passthrough: [NODE_*]     # names or globs, on top of the built-in list

servers:                        # "mcpServers" is accepted as an alias
  fs:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem@2026.8.31", "${GUARDRAILS_SANDBOX:-/tmp/guardrails-sandbox}"]

  github:
    command: docker
    args: ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
           "ghcr.io/github/github-mcp-server@sha256:..."]
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: ${GITHUB_TOKEN}

  docs:
    type: http                  # http (Streamable HTTP) | sse ; omitted means stdio
    url: https://mcp.example.com/mcp
    headers:
      Authorization: "Bearer ${DOCS_MCP_TOKEN}"
    optional: true              # start without it if it is down

  legacy:
    disabled: true
    command: uvx
    args: ["mcp-server-fetch==2025.4.7"]
```

| Field | Applies to | Notes |
|---|---|---|
| `type` | all | `stdio` (the default when `command` is set), `http` (alias `streamable-http`) or `sse`. A `url` with no `type` is an error. |
| `command`, `args` | stdio | `command` must be an absolute path or a name found on PATH. A relative path is refused. |
| `env` | stdio | Values may be strings, numbers, booleans or `null`. Quote a number to keep it exactly as written. |
| `env_file` (or `envFile`) | stdio | `KEY=VALUE` lines. `#` comments and `export ` are allowed. Explicit `env` wins over the file. |
| `cwd` | stdio | Must exist. Relative paths start from the servers file's directory. |
| `shutdown_timeout` | stdio | `500ms`, `5s`, `2m`, or a number of seconds. |
| `env_isolation`, `env_passthrough` | stdio | See [Environment isolation](#environment-isolation). |
| `url` | http, sse | https, or plain http to a loopback address only. No credentials in the URL. |
| `headers` | http, sse | Static, sent with every request. |
| `optional` | all | Start without this server if it can't be reached. Its tools are then absent for the session. |
| `disabled` | all | Skipped entirely: not validated, not connected. |
| `x-guardrails` | all | Reserved for proxy-only options in later versions. |

**Unknown keys are errors.** Silently ignoring a misspelt security option is the
fail-open this project exists to avoid. Keys that only configure a client
(`timeout`, `alwaysLoad`, `oauth`, `auth`, `headersHelper`, `dev`,
`sandboxEnabled`, `transportType`) are ignored, with a warning that says so.

**A remote server is never auto-detected.** `type: http` means Streamable HTTP
and `type: sse` means the older transport. The SDK's auto-detection falls back
to SSE silently, which would be a downgrade nobody chose, so the proxy never
uses it.

**A remote server that is down stops the proxy from starting** unless it is
marked `optional: true`. A proxy that quietly serves a subset of the tools you
configured is serving a tool set nobody reviewed.

## Variables

`${VAR}` and `${VAR:-default}`, as Claude Code writes them. `${env:VAR}`, as
Cursor and VS Code write them, is an alias. `$$` is a literal `$`. The default
applies when the variable is unset *or empty*, as in a shell.

Variables are expanded only in `command`, `args`, `env`, the `env_file` path,
`cwd`, `url` and `headers`. They are never expanded across the whole file.

**An unset variable with no default stops the proxy from starting.** The error
names the server, the field and the variable. Claude Code instead passes the
literal `${VAR}` text through, which means a request goes out with
`Bearer ${TOKEN}` in it, or a server launches against a path that doesn't
exist. This proxy refuses instead.

What's shown in `list-upstream`, `validate` and the audit log is always the
*template*, never what it expanded to. Anything shaped like a secret that was
written into the file literally is masked there too.

## Environment isolation

A child process normally inherits its parent's whole environment. For this
proxy that environment can hold `ANTHROPIC_API_KEY` (for the classifier),
`GUARDRAILS_HTTP_TOKEN`, the webhook signing secret, and every other server's
token. Your threat model already treats a downstream server as possibly hostile.

With `env_isolation: true` a stdio server gets only:

- the built-in list: `PATH`, `HOME`, `USER`, `LANG`, `TMPDIR`, `TEMP`, `TMP`,
  `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `SystemRoot`, `ComSpec`, `PATHEXT`;
- whatever `env_passthrough` names, either in `defaults` or on the server.
  Entries are names or globs (`NODE_*`, matched case-sensitively);
- its own `env` and `env_file`.

`env_passthrough: ["*"]` passes everything through again, with a warning.

**This release warns before it changes anything.** When `env_isolation` is not
set, a server still inherits everything, as before. The proxy writes one warning
per server at startup listing the *names* (never the values) of the variables
isolation would withhold. Isolation will become the default in a future release.
To silence the warning, choose now:

- `env_isolation: true` means isolate, and add whatever the server needs to
  `env_passthrough`;
- `env_isolation: false` means keep inheriting, deliberately.

The built-in filesystem server used when there is no servers file is not
affected.

## Per-server policy

Rules can be scoped to a server by name with `server:`, a glob like `tool:`:

```yaml
rules:
  - name: approve-github-writes
    match:
      server: github
      annotations: { readOnlyHint: false }
    decision: require_approval
```

See [policy.md](policy.md#what-a-rule-can-match-on).

`mcp-guardrails init` writes rules like these for you: it recognizes popular
servers in this file by their package, image or URL and generates a policy from
the matching [packs](packs.md).

## Checking a file: `validate`

```bash
mcp-guardrails validate --servers servers.yaml --policy policy.yaml
```

This loads both files and checks them without launching anything. It reports
**every** error and warning at once, and exits 0 if the proxy would start, 1 if
not, so you can run it in CI against a committed servers file. As well as each
field, it checks that commands resolve, that `cwd` and `env_file` exist, and
that every variable is set. It also warns about a policy rule whose `server:`
matches no configured server, and about a servers file that other users can
write.

`list-upstream` goes one step further. It connects to every server and prints
the tools they advertise, qualified as the client will see them. It also says
which servers have no [pins](pins.md) yet and which tools changed since they
were pinned, without pinning anything itself.

## Security notes

- **The servers file is code execution.** Whoever can write it chooses what the
  proxy launches. Keep it as private as a shell script you run on login. On Unix
  the proxy warns if the file is group- or world-writable.
- **No hot reload.** Changes take effect on restart, which is explicit and shows
  up in the audit log as a new set of `upstream_connected` lines.
- **Redirects are not followed** for remote servers. A 3xx would carry your
  `Authorization` header to a host you never named.
