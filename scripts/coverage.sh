#!/usr/bin/env bash
#
# Run the tests with coverage and enforce a minimum.
#
# Used identically by developers and by CI, so a green local run means a green
# pipeline. Prints a per-class table on failure so you can see what regressed.
#
#   scripts/coverage.sh              # use the thresholds below
#   MIN_LINE=90 scripts/coverage.sh  # override
#
set -euo pipefail

# Core currently sits at 100/100. The gate is set there deliberately: it is a
# ratchet, so an untested branch fails the build the moment it is introduced,
# while the reason is still fresh.
#
# Escape hatch for genuinely untestable code (platform-specific paths, defensive
# branches that cannot be provoked): annotate it [ExcludeFromCodeCoverage] with a
# comment explaining why. That is a visible, reviewable decision - unlike quietly
# lowering the threshold, which hides the loss.
MIN_LINE="${MIN_LINE:-100}"
MIN_BRANCH="${MIN_BRANCH:-100}"
RESULTS_DIR="${RESULTS_DIR:-artifacts/coverage}"

cd "$(dirname "$0")/.."

rm -rf "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

dotnet test \
  --settings coverlet.runsettings \
  --collect:"XPlat Code Coverage" \
  --results-directory "$RESULTS_DIR" \
  --nologo

REPORT="$(find "$RESULTS_DIR" -name 'coverage.cobertura.xml' | head -1)"

if [ -z "$REPORT" ]; then
  echo "::error::no coverage report was produced" >&2
  exit 1
fi

cp "$REPORT" "$RESULTS_DIR/coverage.cobertura.xml" 2>/dev/null || true

MIN_LINE="$MIN_LINE" MIN_BRANCH="$MIN_BRANCH" REPORT="$REPORT" python3 - <<'PY'
import os
import sys
import xml.etree.ElementTree as ET

report = os.environ["REPORT"]
min_line = float(os.environ["MIN_LINE"])
min_branch = float(os.environ["MIN_BRANCH"])

root = ET.parse(report).getroot()
line = float(root.get("line-rate", 0)) * 100
branch = float(root.get("branch-rate", 0)) * 100

classes = []
for cls in root.iter("class"):
    name = (cls.get("name") or "?").split(".")[-1]
    lr = float(cls.get("line-rate", 0)) * 100
    br = float(cls.get("branch-rate", 0)) * 100
    missed = sorted({
        int(ln.get("number"))
        for ln in cls.iter("line")
        if ln.get("hits") == "0"
    })
    classes.append((lr, br, name, missed))

print()
print(f"{'class':<34}{'line':>8}{'branch':>9}  uncovered lines")
print("-" * 78)
for lr, br, name, missed in sorted(classes):
    shown = ",".join(map(str, missed[:12])) + ("…" if len(missed) > 12 else "")
    print(f"{name:<34}{lr:>7.1f}%{br:>8.1f}%  {shown}")

print("-" * 78)
print(f"{'TOTAL':<34}{line:>7.1f}%{branch:>8.1f}%")
print(f"{'REQUIRED':<34}{min_line:>7.1f}%{min_branch:>8.1f}%")
print()

failed = False
if line < min_line:
    print(f"::error::line coverage {line:.1f}% is below the required {min_line:.1f}%")
    failed = True
if branch < min_branch:
    print(f"::error::branch coverage {branch:.1f}% is below the required {min_branch:.1f}%")
    failed = True

if failed:
    sys.exit(1)

print(f"coverage OK  (line {line:.1f}% >= {min_line:.1f}%, branch {branch:.1f}% >= {min_branch:.1f}%)")
PY
