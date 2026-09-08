# Contributing

Thanks for looking. This document covers how the repository is organised and the
conventions the history follows.

## Getting set up

Requirements:

- .NET 10 SDK (the version in [`global.json`](global.json))
- Node.js — only to run downstream MCP servers via `npx` during tests
- Python 3 — only for `scripts/smoke.py`

```bash
dotnet build
dotnet test
python3 scripts/smoke.py     # end-to-end, spawns a real downstream server
```

All three must pass before a change is considered done. CI runs exactly these on
Linux, macOS and Windows.

## Branching

`main` is always releasable. Nothing is committed to it directly.

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
