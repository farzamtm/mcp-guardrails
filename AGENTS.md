# AGENTS.md

Rules for any coding agent working in this repository. They are not
suggestions: three of them are enforced by git hooks, and the rest exist
because this project is a security tool and a careless push is a bad look.

Humans should read [CONTRIBUTING.md](CONTRIBUTING.md) — it covers the same
ground in more detail. This file is the short, imperative version.

## One-time setup

```bash
git config core.hooksPath .githooks
```

Without this the hooks in [`.githooks/`](.githooks) do nothing. Check it before
your first commit in a fresh clone:

```bash
git config --get core.hooksPath   # must print: .githooks
```

The hooks catch mistakes early, on your machine. They are local and
bypassable — treat them as a reminder system, not as a security boundary.

The boundary is server-side: the ruleset in
[`.github/rulesets/main.json`](.github/rulesets/main.json), applied with
`scripts/apply-branch-protection.sh`. `main` moves only through a pull request
with passing CI; only the maintainer can merge without an approving review
(GitHub forbids approving your own PR — see
[`.github/rulesets/README.md`](.github/rulesets/README.md)). Do not apply the
ruleset, change it, or change the repository's visibility or settings without
being asked.

## The four rules

### 1. Work happens on a feature branch, never on `main`

Before the first edit of a task, not after:

```bash
git fetch origin
git switch -c <type>/<short-description> origin/main
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`,
`style` — the same set as commit messages.

Branch off `origin/main` unless the work genuinely builds on another open
branch. If you are already on someone's feature branch and the new task is
unrelated, branch off `main` anyway.

`.githooks/pre-commit` refuses commits on `main`, `master` and on a detached
HEAD.

### 2. Ask before committing

Show the human what you are about to commit and the message you intend to use,
then wait for a yes. Do not commit as a reflex at the end of a task.

```bash
git status
git diff            # and git diff --staged
```

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
— `<type>: <imperative summary>` plus a body explaining *why*. One logical
change per commit.

Never `git add -A` blindly; stage the files you actually touched.

### 3. Run the whole pipeline, and ask, before pushing

```bash
scripts/preflight.sh
```

This is [`.github/workflows/ci.yml`](.github/workflows/ci.yml) executed
locally: `dotnet format --verify-no-changes`, a Release build with warnings as
errors, `dotnet test`, the coverage gate (`scripts/coverage.sh`, 100% line and
branch), `ruff`, `shellcheck`, the end-to-end smoke test against a real
downstream MCP server, and a parse check of every example policy.

It must be green **before** you ask. Then ask — pushing is the human's call,
every time. `.githooks/pre-push` runs preflight itself and refuses any push to
`main`, so a push that skips the checks has to be deliberate.

Rules about the gate:

- Do not "fix" a failure by weakening it. Lowering the coverage threshold,
  deleting an assertion or adding `--no-verify` to a command is not a fix.
- If preflight cannot run at all (missing SDK, no network for `npx`), say so
  and stop. Do not report the work as verified.
- `FAST=1 scripts/preflight.sh` (format, build, test only) is for tightening an
  inner loop, never for the final check before a push.

### 4. Ask before opening a pull request

Draft the title and body, show them, wait for a yes. `main` only ever moves
through a reviewed PR.

```bash
gh pr create --base main --head <your-branch>
```

The body says why the change exists and how it was verified.

## Never without being asked

- `git push --force` / `--force-with-lease`, or any history rewrite on a shared
  branch
- `git push --no-verify`, `git commit --no-verify`
- Pushing, merging or committing to `main`
- Changing repository settings, secrets, workflow permissions or action pins
- Adding a dependency, or bumping one, as a side effect of unrelated work
- Deleting or renaming a branch on the remote

## Project facts worth knowing

- .NET 10 (see [`global.json`](global.json)); `Directory.Build.props` sets
  `TreatWarningsAsErrors`, so a warning is a build failure.
- Coverage is a ratchet at 100% line and branch. Genuinely untestable code gets
  `[ExcludeFromCodeCoverage]` with a comment explaining why — a visible,
  reviewable decision, unlike lowering the gate.
- Third-party GitHub Actions are pinned to commit SHAs with the human-readable
  tag in a comment. Keep it that way; a mutable tag is an execution path into
  CI.
- `scripts/smoke.py` spawns a real downstream MCP server over `npx`, so it
  needs Node and network access on first run.
- Comments explain *why*. The diff already shows what changed.
