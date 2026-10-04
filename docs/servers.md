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
| `x-guardrails` | all | Options only the proxy reads: `oauth` (remote servers), see [Logging in with OAuth](#logging-in-with-oauth), and `isolation` (stdio servers), see [Container isolation](#container-isolation). Unknown keys inside it are errors too. |

**Unknown keys are errors.** Silently ignoring a misspelt security option is the
fail-open this project exists to avoid. Keys that only configure a client
(`timeout`, `alwaysLoad`, `oauth`, `auth`, `headersHelper`, `dev`,
`sandboxEnabled`, `transportType`) are ignored, with a warning that says so.
A client's `oauth` key configures the client's own login; to have the proxy log
in to a remote server, use `x-guardrails: { oauth: {} }` and `auth login`
([below](#logging-in-with-oauth)).

**A remote server is never auto-detected.** `type: http` means Streamable HTTP
and `type: sse` means the older transport. The SDK's auto-detection falls back
to SSE silently, which would be a downgrade nobody chose, so the proxy never
uses it.

**A remote server that is down stops the proxy from starting** unless it is
marked `optional: true`. A proxy that quietly serves a subset of the tools you
configured is serving a tool set nobody reviewed.

## Logging in with OAuth

Many remote servers (GitHub, Atlassian, Linear) want an OAuth login rather than
a static token. Mark them with an `x-guardrails.oauth` block:

```yaml
servers:
  linear:
    type: http
    url: https://mcp.linear.app/mcp
    x-guardrails:
      oauth: {}                  # or { scopes: [read, write] }
```

Then log in once, from a terminal:

```bash
mcp-guardrails auth login linear     # opens a browser; --no-browser prints the URL
mcp-guardrails auth status           # who is logged in, and until when
mcp-guardrails auth logout linear    # deletes the tokens
```

`auth login` follows the MCP authorization spec: it finds the server's
authorization server from its protected resource metadata, registers itself
(dynamic client registration) unless you give a `client_id`, and runs the
authorization code flow with PKCE through your browser, which comes back to a
listener on `127.0.0.1`.

| Option | Default | Meaning |
| --- | --- | --- |
| `scopes` | the server's suggestion | Scopes to ask for. |
| `client_id` | dynamic registration | A client registered in advance, for servers without dynamic registration. |
| `redirect_port` | any free port | The loopback port for the redirect, for a `client_id` registered with a fixed one. |

**When the proxy serves, it never opens a browser.** It uses the stored tokens
and refreshes them when they expire. A server with no usable login does not stop
the proxy: its tools are absent, a warning names the server, and a call to one
of them tells the model to have you run `auth login`. The same happens when a
login expires mid-session and cannot be refreshed, and when the credential store
cannot be read (a locked Keychain or keyring): one server's credential trouble
never stops the others. A refresh that returns no new refresh token keeps the
stored one, as servers that do not rotate them expect. A server that was never
logged in is not contacted at all, so starting the proxy registers no clients.

**Where the tokens live**, never in the servers file or the audit log:

| Platform | Store |
| --- | --- |
| macOS | The login Keychain, through `security` (the secret is passed on stdin, never on a command line) |
| Linux | The Secret Service (GNOME Keyring, KWallet) through libsecret's `secret-tool`; without one, files as below, with a warning |
| Windows | Files encrypted with DPAPI for your user |
| Anywhere, with `GUARDRAILS_TOKEN_STORE=file` | `~/.mcp-guardrails/tokens/<server>.json` (or `GUARDRAILS_TOKENS`), created `0600` in a `0700` directory |

`GUARDRAILS_TOKEN_STORE` also accepts `keychain`, `secret-service` and `dpapi`,
each only on its own platform. On Windows, `file` writes unencrypted files
protected only by the folder's permissions; prefer the DPAPI default.

The macOS Keychain items are readable by any process running as you, through the
same `security` tool, without a prompt. Against other software running as your
user they protect no more than the `0600` file; what they add is that the tokens
are not a file to copy, back up or commit by accident.

`auth login` reads the item back after writing it and fails if it differs, so a
login too large for the store is an error at login rather than a broken login
later.

**Tokens are bound to the server's URL.** If you point a server name at a
different URL, the old login is not sent there; `auth status` says so, and you
log in again.

A server with `x-guardrails.oauth` cannot also send a static `Authorization`
header, and stdio servers cannot use it.

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

## Container isolation

Environment isolation keeps the proxy's secrets away from a server. It does
nothing about the server's own access to your files and network. For that, run
it in a container:

```yaml
servers:
  fetch:
    command: uvx
    args: ["mcp-server-fetch==2025.4.7"]
    x-guardrails:
      isolation:
        image: ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:...
        network: bridge
```

The proxy launches it through `docker run` (or `podman run`) with no network,
a read-only root, all capabilities dropped and only the folders you mount.
Its variables are passed by name, never on the command line. If the runtime
is missing, the proxy refuses to start rather than run the server without its
container. See [isolation.md](isolation.md).

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
were pinned, without pinning anything itself. [`scan`](scan.md) checks the same
tool definitions for injection-shaped text, suspicious schema defaults and
dishonest read-only hints, and exits non-zero on a finding, for CI.

## Security notes

- **The servers file is code execution.** Whoever can write it chooses what the
  proxy launches. Keep it as private as a shell script you run on login. On Unix
  the proxy warns if the file is group- or world-writable.
- **No hot reload.** Changes take effect on restart, which is explicit and shows
  up in the audit log as a new set of `upstream_connected` lines.
- **Redirects are not followed** for remote servers. A 3xx would carry your
  `Authorization` header to a host you never named.
