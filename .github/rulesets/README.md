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

The repository is public, so the rulesets API is available. The local hooks in
[`../../.githooks`](../../.githooks) stay as an early warning - they catch a
commit on `main` before it is made - but they are bypassable with
`--no-verify`; the ruleset is not.

## What it enforces

| Rule | Effect |
| --- | --- |
| `pull_request` | `main` moves only through a PR with **one approving review**. Stale reviews are dismissed on push, the last pusher cannot self-approve, review threads must be resolved. Merge commits and squash merges are allowed. |
| `required_status_checks` | `lint`, `build & test` on all three OSes, `coverage gate` and `end-to-end smoke` must pass, and the branch must be up to date with `main` first (`strict`). |
| `non_fast_forward` | No force-pushes. |
| `deletion` | `main` cannot be deleted. |
| `bypass_actors` | Repository admins - the maintainer - may bypass, **only by merging a pull request** (`bypass_mode: pull_request`). Nobody can push to `main` directly. |

### Why the maintainer can bypass the review

GitHub does not let anyone approve their own pull request, and this repository
has one maintainer, whose account also opens the PRs its agents prepare. With a
required review and no bypass, every one of those PRs would wait forever for an
approval that cannot arrive.

So the review requirement stands for everyone else - a contributor's PR needs
the maintainer's approval - and the maintainer's own PRs are merged with
"Merge without waiting for requirements to be met", which GitHub records as a
bypass by that account. The maintainer's merge *is* the approval. Because the
bypass works only through a pull request, the PR, its diff and its CI run still
exist for every change; what it skips is the approval step, not the review
trail. Add a second maintainer and the bypass can go.

### Why there is no linear-history rule

GitHub's "require linear history" blocks merge commits on `main` outright - the
"Create a merge commit" button disappears - and this repository merges with
merge commits (see [CONTRIBUTING.md](../../CONTRIBUTING.md)). The rule would
contradict the workflow, so it is not part of the ruleset.

### Status check names

The contexts must match the job names in
[`../workflows/ci.yml`](../workflows/ci.yml) exactly. Rename a job and the old
context never reports again — a required check that never arrives blocks every
PR forever. Change both in the same commit.
