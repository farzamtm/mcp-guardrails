#!/usr/bin/env bash
#
# Push .github/rulesets/main.json to GitHub.
#
# Branch protection that only exists in the web UI is invisible in review,
# undiffable, and gone the day someone clicks the wrong toggle. This applies the
# committed definition instead, and is idempotent: it updates the existing
# ruleset of the same name rather than stacking duplicates.
#
#   scripts/apply-branch-protection.sh            # apply or update
#   scripts/apply-branch-protection.sh --show     # what is live right now
#   scripts/apply-branch-protection.sh --dry-run  # what would be sent
#
# Needs the gh CLI, authenticated with admin on the repository.
set -euo pipefail

cd "$(dirname "$0")/.."

CONFIG="${CONFIG:-.github/rulesets/main.json}"
MODE="${1:-apply}"

fail() { printf '\033[1;31m%s\033[0m\n' "$*" >&2; exit 1; }
info() { printf '\033[1;34m%s\033[0m\n' "$*"; }

command -v gh >/dev/null 2>&1 || fail "this needs the gh CLI: https://cli.github.com"
[ -f "$CONFIG" ] || fail "no ruleset definition at $CONFIG"

REPO="${REPO:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"
NAME="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$CONFIG")"

# The free plan does not expose this API at all, and the 403 it returns says
# nothing about your permissions - so say the useful thing instead of letting a
# raw HTTP error stand as the explanation.
plan_guard() {
  local out="$1"
  case "$out" in
    *"Upgrade to GitHub Pro"*)
      cat >&2 <<EOF

  ✗ GitHub will not serve the rulesets API for this repository.

    $REPO is private on the free plan. Rulesets and branch protection need
    either a public repository or a paid plan:

        gh repo edit $REPO --visibility public --accept-visibility-change-consequences

    Until then the local hooks in .githooks are the fallback - see
    .github/rulesets/README.md.

EOF
      exit 1
      ;;
  esac
}

case "$MODE" in
  --dry-run)
    info "would PUT/POST this to $REPO:"
    cat "$CONFIG"
    exit 0
    ;;
  --show)
    out="$(gh api "repos/$REPO/rulesets" 2>&1)" || { plan_guard "$out"; fail "$out"; }
    echo "$out" | python3 -m json.tool
    exit 0
    ;;
  apply) ;;
  *) fail "unknown argument: $MODE (expected --show, --dry-run, or nothing)" ;;
esac

info "reading existing rulesets on $REPO"
existing="$(gh api "repos/$REPO/rulesets" 2>&1)" || { plan_guard "$existing"; fail "$existing"; }

# The payload goes in through the environment, not stdin: the here-doc already
# owns stdin, and two redirections on one command is a race nobody wins.
id="$(
  NAME="$NAME" RULESETS="$existing" python3 - <<'PY'
import json, os

name = os.environ["NAME"]
try:
    rulesets = json.loads(os.environ["RULESETS"])
except json.JSONDecodeError:
    rulesets = []
if not isinstance(rulesets, list):
    rulesets = []
print(next((str(r["id"]) for r in rulesets if r.get("name") == name), ""))
PY
)"

if [ -n "$id" ]; then
  info "updating ruleset '$NAME' (id $id)"
  gh api --method PUT "repos/$REPO/rulesets/$id" --input "$CONFIG" > /dev/null
else
  info "creating ruleset '$NAME'"
  gh api --method POST "repos/$REPO/rulesets" --input "$CONFIG" > /dev/null
fi

printf '\033[1m%s\033[0m\n' "Ruleset '$NAME' is live on $REPO. Verify with --show."
