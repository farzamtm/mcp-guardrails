# Container isolation

The proxy decides *which calls* reach a server. It does not decide what the
server process does with your machine: a stdio server runs as you, and a
malicious or compromised one can read `~/.ssh`, call the network or persist
itself without any tool call at all.

`x-guardrails.isolation` runs a stdio server inside a container instead. The
server sees only the folders you mount, gets no network unless you allow it,
cannot write to its own image, and runs without root and without capabilities.

```yaml
servers:
  fetch:
    command: uvx
    args: ["mcp-server-fetch==2025.4.7"]
    x-guardrails:
      isolation:
        image: ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:...
        network: bridge              # fetch needs the internet; most servers don't
  fs:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem@2026.8.31", "/workspace"]
    x-guardrails:
      isolation:
        image: node:22-alpine@sha256:...
        mounts:
          - { host: "${GUARDRAILS_SANDBOX}", container: /workspace, mode: rw }
```

`command` and `args` now run **inside the image**, so `/workspace` above is the
container's path, not yours. If the image has an `ENTRYPOINT`, they are passed
to it as arguments, as `docker run image command args` always does.

## How it works

The proxy does not talk to a container daemon. It turns the block into an
ordinary command line and launches that like any other stdio server:

```text
docker run -i --rm --label mcp-guardrails.server=fs --network none --cap-drop ALL
  --security-opt no-new-privileges --pids-limit 256 --memory 512m --cpus 1
  --user 501:20 --read-only --tmpfs /tmp:rw,exec,nosuid,nodev,size=256m -e HOME=/tmp
  --mount type=bind,source=/tmp/guardrails-sandbox,target=/workspace
  -e GITHUB_TOKEN
  node:22-alpine@sha256:... npx -y @modelcontextprotocol/server-filesystem@2026.8.31 /workspace
```

There is no Docker API client and no socket handling in the proxy. The runtime's
own CLI already does that, and a command line is something you can read, paste
into a terminal and run by hand. `validate` prints the generated command for
every isolated server, and the line under it says what the server can reach:

```text
  fs                   stdio  docker run -i --rm ... node:22-alpine@sha256:... npx ...
                              can reach: docker container from node:22-alpine@sha256:...; network none;
                              /tmp/guardrails-sandbox as /workspace (read-write); root filesystem
                              read-only; user 501:20; memory 512m, 1 CPU, 256 processes
```

A server that is not isolated gets a line saying so, too.

## Options

| Field | Default | Notes |
|---|---|---|
| `image` | required | The image to run. Pin it by digest (`image@sha256:...`): a tag can be moved to a different image, and `validate` warns about one that isn't pinned. |
| `runtime` | detected | `docker` or `podman`. When omitted, the first of `docker`, `podman` found on PATH. |
| `network` | `none` | `none`, or `bridge` for ordinary outbound access. `host` is refused because it undoes the isolation. `allowlist` is reserved and refused until it exists. |
| `mounts` | none | `{ host, container, mode }`. `mode` is `ro` (default) or `rw`. Relative host paths start from the servers file's directory. |
| `read_only_root` | `true` | The image's own filesystem is read-only. `/tmp` is a writable in-memory scratch space either way, and `HOME` points at it. |
| `memory` | `512m` | A size: digits with an optional `b`, `k`, `m` or `g`. |
| `cpus` | `1` | Any number greater than 0, e.g. `0.5`. |
| `pids_limit` | `256` | The most processes the container may run. |
| `user` | your `uid:gid` | So files written into a `rw` mount belong to you rather than to root. Where it can't be read (Windows, or `id` failing) the server runs as `65534:65534` (nobody). Root (`0`, `root`) is allowed, with a warning. |

Unknown keys are errors, like everywhere else in the servers file.

## Environment variables

A container gets **only the variables declared in `env` and `env_file`**, and it
gets them by name: the generated command says `-e GITHUB_TOKEN`, never
`-e GITHUB_TOKEN=ghp_...`. The runtime copies the value from its own environment,
which the proxy sets. A secret therefore never appears on a command line that
`ps` would show any local user, and never in the audit log.

The `docker`/`podman` process itself gets the built-in list from
[environment isolation](servers.md#environment-isolation) (`PATH`, `HOME`, ...)
plus `DOCKER_*`, `CONTAINER_*`, `CONTAINERS_*` and `XDG_*`, which is what it needs
to find its daemon or context. None of those reach the container.

So on an isolated server:

- `env_passthrough` and `env_isolation` are errors. Pass a variable through with
  `env: { NAME: ${NAME} }`.
- `env` may not set a variable the runtime reads itself (`PATH`, `HOME`,
  `DOCKER_HOST`, ...). Set it in the image instead.
- `defaults.env_passthrough` and `defaults.env_isolation` do not apply.

## Rules the loader enforces

- **No runtime, no server.** If isolation is configured and the runtime is not on
  PATH, that is a startup error. The proxy never falls back to running the server
  directly on the host. A runtime whose daemon is down fails the connection, which
  is also a startup error unless the server is `optional: true`.
- **Mounts are explicit.** Your home directory is never mounted for you. Mounting
  it, or a folder above it, works but warns, because it hands over your SSH keys,
  cloud credentials and browser profiles.
- **No runtime socket.** Mounting `docker.sock` or `podman.sock` is refused:
  whoever holds the socket controls the host.
- **No `cwd`.** The command runs inside the image, where host directories don't
  exist; mount what it needs instead.
- **The command is not looked up on your PATH.** It runs in the image, so the
  host doesn't need `uvx` or `npx` installed. The runtime is looked up instead.
- Paths with a comma, a quote or a control character are refused, because the
  mount syntax can't carry them. The image can't start with `-`, so it can't be
  mistaken for a flag. The server's own `args` come after the image, so they can
  never become runtime flags.

## Pins and the audit log

The `upstream_connected` audit line records the generated `docker run` command,
built from the servers file's templates (`${SANDBOX}`, not what it expanded to).

[Pins](pins.md) identify a stdio server by its command line, and for an isolated
server that is the generated command. Turning isolation on, or changing the image
or a mount, therefore shows up as `identity_changed` on the next start: the
program answering under that name really did change. Accept it with
`pins accept <server>`.

## What isolation does not protect against

- **A container escape.** A kernel or runtime vulnerability that breaks out of
  the container is out of scope. Containers share the host kernel. For a stronger
  boundary, run the runtime with gVisor or inside a VM.
- **Whatever you mount.** A `rw` mount is fully writable by the server, and a
  `ro` mount fully readable. Mount the narrowest folder that works.
- **`network: bridge`.** The server can reach anything your machine can,
  including services on your local network. A per-host allowlist is planned.
- **What it sends back through the proxy.** Results still go through the result
  scanner and secret redaction, as for any server. Isolation doesn't change what
  it can say to the model.
- **The image itself.** An image you didn't build is code you didn't review.
  Pinning by digest makes it the same code every time, not trusted code.
- **The container daemon.** Rootful Docker's daemon runs as root. A rootless
  runtime (rootless Docker, or Podman) limits what a runtime compromise can do.
- **Rootless Podman and `rw` mounts.** Rootless Podman maps container users onto
  subordinate ids, so a file written as `--user 501:20` may not belong to you on
  the host. If writes to a `rw` mount fail, set `user:` to fit your setup.

## Not yet

- A network allowlist, through a filtering sidecar.
- Linux `bubblewrap` and macOS `sandbox-exec` for machines without a container
  runtime.
- Choosing a stronger container runtime such as gVisor (`--runtime runsc`).
