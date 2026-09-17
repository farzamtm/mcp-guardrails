# Branch protection

[`main.json`](main.json) is the server-side protection for the default branch,
kept in git so the rule is reviewable and restorable rather than living only in
somebody's browser tab.

Apply or update it:

```bash
scripts/apply-branch-protection.sh            # apply / update
scripts/apply-branch-protection.sh --show     # print what is live today
scripts/apply-branch-protection.sh --dry-run  # print what would be sent
```

## It cannot be applied yet

The repository is **private on the GitHub free plan**, where the rulesets and
branch-protection APIs are unavailable:

```text
403 Upgrade to GitHub Pro or make this repository public
```

So the file is a declaration of intent with a one-command path to reality the
moment either of these is true:

- the repository becomes public, or
- the account moves to GitHub Pro (or the repo moves into an org on Team).

Until then the local hooks in [`../../.githooks`](../../.githooks) approximate
it: no commits on `main`, no pushes to `main`, and the full pipeline runs
before any push. They are bypassable with `--no-verify`; the ruleset is not.
That gap is the reason this file exists.

## What it enforces

| Rule | Effect |
| --- | --- |
| `pull_request` | `main` moves only through a PR. Stale reviews are dismissed on push, the last pusher cannot self-approve, review threads must be resolved. |
| `required_status_checks` | `lint`, `build & test` on all three OSes, `coverage gate` and `end-to-end smoke` must pass, and the branch must be up to date with `main` first (`strict`). |
| `non_fast_forward` | No force-pushes. |
| `deletion` | `main` cannot be deleted. |
| `required_linear_history` | No merge commits with a tangled ancestry landing on `main`. |
| `bypass_actors: []` | Nobody bypasses, admins included. |

### Two knobs to revisit

- **`required_approving_review_count: 0`.** GitHub does not let you approve
  your own pull request, so on a single-maintainer repository any number above
  zero makes `main` unmergeable. Raise it to `1` the day a second maintainer
  exists. Everything else — the PR, the checks, the resolved threads — is
  enforced at `0`.
- **`required_linear_history` vs `--no-ff` merges.** CONTRIBUTING.md asks for
  `--no-ff` merges into `main`. That stays legal: linear history forbids a
  merge whose *branch* has merge commits in it, not the merge commit itself.
  Rebase your branch on `main` before merging.

### Status check names

The contexts must match the job names in
[`../workflows/ci.yml`](../workflows/ci.yml) exactly. Rename a job and the old
context never reports again — a required check that never arrives blocks every
PR forever. Change both in the same commit.
