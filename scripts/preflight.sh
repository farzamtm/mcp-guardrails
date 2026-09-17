#!/usr/bin/env bash
#
# Run everything CI runs, locally, before anything leaves the machine.
#
# .github/workflows/ci.yml is the contract; this script is the same contract
# executed on your laptop. A green run here means the pipeline has no new
# information to give you - which is the point: finding out on GitHub, ten
# minutes after a push, that `dotnet format` disagrees with you is a waste of
# everyone's attention.
#
#   scripts/preflight.sh          # everything
#   FAST=1 scripts/preflight.sh   # format + build + test only, no coverage/e2e
#
# The pre-push hook calls this. If you need to bypass it you are choosing to
# push something unverified, so do it deliberately with `git push --no-verify`
# rather than by weakening this script.
set -euo pipefail

cd "$(dirname "$0")/.."

FAST="${FAST:-0}"
CONFIG="${CONFIG:-Release}"
BIN="src/McpGuardrails.Cli/bin/$CONFIG/net10.0/McpGuardrails.Cli"

# Pinned to the same version CI installs. A linter that changes its mind
# between runs turns a green push red without anyone writing code.
RUFF_VERSION="0.16.6"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
fail() {
  printf '\033[1;31m%s\033[0m\n' "$*" >&2
  exit 1
}

require() {
  command -v "$1" >/dev/null 2>&1 || fail "preflight needs '$1' on PATH ($2)"
}

# ruff is not a system package here the way dotnet is, so fall back through the
# usual ephemeral runners before giving up. Silently skipping the lint would be
# worse than failing: the push would go out and CI would catch it anyway.
ruff_cmd() {
  if command -v ruff >/dev/null 2>&1; then
    ruff "$@"
  elif command -v uvx >/dev/null 2>&1; then
    uvx "ruff@$RUFF_VERSION" "$@"
  elif command -v pipx >/dev/null 2>&1; then
    pipx run "ruff==$RUFF_VERSION" "$@"
  else
    fail "preflight needs ruff (pipx install ruff==$RUFF_VERSION)"
  fi
}

require dotnet "https://dotnet.microsoft.com/download"
require python3 "needed by scripts/coverage.sh and scripts/smoke.py"

START=$SECONDS

step "format (dotnet format --verify-no-changes)"
dotnet format --verify-no-changes

step "build ($CONFIG, warnings are errors)"
dotnet build --configuration "$CONFIG" --nologo

step "test ($CONFIG)"
dotnet test --no-build --configuration "$CONFIG" --nologo

if [ "$FAST" = "1" ]; then
  bold $'\nFAST=1: skipped coverage, lint and end-to-end. CI still runs them.'
  exit 0
fi

step "coverage gate (scripts/coverage.sh)"
./scripts/coverage.sh

step "lint python (ruff)"
ruff_cmd check scripts
ruff_cmd format --check scripts

step "lint shell (shellcheck)"
require shellcheck "brew install shellcheck"
shellcheck scripts/*.sh

step "end-to-end smoke through a real downstream server"
require node "needed to spawn the downstream MCP server via npx"
python3 scripts/smoke.py "$BIN"

# Examples are documentation, and documentation rots. A malformed policy is a
# fatal startup error, so a non-zero exit here means we were about to ship an
# example nobody could use.
step "validate example policies"
for policy in examples/*.yaml; do
  echo "checking $policy"
  GUARDRAILS_POLICY="$policy" "$BIN" list-upstream >/dev/null
done

bold $'\nPreflight passed in '"$((SECONDS - START))"$'s - CI should agree.'
