# Contributing

Thanks for looking. This document covers how the repository is organised and the
conventions the history follows.

## Getting set up

Requirements:

- .NET 10 SDK (the version in [`global.json`](global.json))
- Node.js — only to run downstream MCP servers via `npx` during tests
- Python 3 — only for `scripts/smoke.py`

```bash
git config core.hooksPath .githooks   # once per clone - see below

dotnet build
dotnet test
python3 scripts/smoke.py     # end-to-end, spawns a real downstream server
```

All three must pass before a change is considered done. CI runs exactly these on
Linux, macOS and Windows.

[`scripts/preflight.sh`](scripts/preflight.sh) runs the entire pipeline —
format, build, test, coverage gate, `ruff`, `shellcheck`, smoke test and the
example-policy check — so a green run locally means CI has nothing new to say.

## Branching

`main` is always releasable. Nothing is committed to it directly.

This is enforced as far as it can be: [`.githooks/`](.githooks) holds a
`pre-commit` that refuses commits on `main` and a `pre-push` that refuses
pushes to `main` and runs `scripts/preflight.sh` first. Hooks are not installed
by cloning, hence the `core.hooksPath` line above. GitHub's own branch
protection is unavailable while the repository is private on a free plan (the
API answers `403 Upgrade to GitHub Pro or make this repository public`), so the
hooks are a reminder, not a boundary — `--no-verify` still works, and using it
is a decision you own.

The server-side rule is committed anyway, in
[`.github/rulesets/main.json`](.github/rulesets/main.json): required PR,
required CI checks, no force-push, no deletion, no bypass. One command applies
it (`scripts/apply-branch-protection.sh`) once the plan allows it. See
[`.github/rulesets/README.md`](.github/rulesets/README.md).

Agents working in this repository follow [AGENTS.md](AGENTS.md), which encodes
the same rules plus "ask before commit, push or PR".

Every change happens on a branch named `<type>/<short-description>`:

```text
feat/policy-engine
fix/tool-name-collision
docs/threat-model
chore/bump-sdk
ci/publish-aot-binaries
```

Branches merge into `main` with `--no-ff`, so the merge commit records that a
group of commits belonged to one piece of work. The graph stays readable as a
sequence of features rather than a flat wall of commits.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>: <imperative summary, lower case, no trailing period>

<body: why the change exists, not what the diff already shows>
```

Types in use: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`,
`style`.

The body is where the value is. Explain the reasoning, the alternative you
rejected, or the failure mode you were guarding against. The diff already shows
what changed.

## History hygiene

- **One logical change per commit.** A commit that adds a feature and reformats
  three unrelated files is two commits.
- **Every commit builds and passes tests.** Someone bisecting a bug should never
  land on a broken revision.
- **Fold up your own noise before opening a PR.** Formatter output, typo fixes
  and "fix previous commit" belong squashed into the commit they correct, not
  preserved as archaeology.
- **Never rewrite history that has been pushed to a shared branch.** Rebase your
  own unpublished work freely; leave everyone else's alone.

## Code conventions

Enforced by the build rather than by review:

- [`Directory.Build.props`](Directory.Build.props) sets
  `TreatWarningsAsErrors`, so warnings are build failures.
- `IsAotCompatible` is on, so the analyzers reject reflection patterns that
  would break Native AOT later. This is why JSON goes through the
  source-generated `GuardrailsJsonContext` instead of `JsonSerializer.Serialize(object)`.
- Nullable reference types are enabled everywhere.

Beyond that:

- Prefer pure functions with no I/O for logic that deserves tests. `ToolNamespacer`
  is the model: no dependencies, exhaustively testable.
- Prefer immutability. Most concurrency in this codebase is handled by building
  state once at startup and never mutating it, which needs no locking at all.
- Comment the *why*. Several comments here exist to record a decision or a trap
  (see the note on `McpClientTool.WithName` in `ToolNamespacer`), not to restate
  the code.

## Tests

- Unit tests (`tests/McpGuardrails.Core.Tests`) cover pure logic and must be fast.
- `scripts/smoke.py` is the integration layer: it speaks real JSON-RPC to the
  built binary and asserts on both the replies and the resulting audit log.
- A bug fix should come with a test that fails without it. The regression test in
  `ToolNamespacerTests.Qualify_Tool_RenamesTheProtocolDto` is the pattern.

## Security

This project is a security tool, so it holds itself to the same standard it
claims to provide:

- GitHub Actions are pinned to commit SHAs, never mutable tags.
- `persist-credentials: false` on checkout.
- Dependencies stay minimal and are justified in review.

Please do not open a public issue for a vulnerability in this tool. See
[SECURITY.md](SECURITY.md).
