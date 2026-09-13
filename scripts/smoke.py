#!/usr/bin/env python3
"""
Minimal MCP stdio driver, for smoke-testing the proxy without Claude Desktop.

Deliberately dependency-free: it speaks newline-delimited JSON-RPC straight at
the child process's stdin and reads replies off stdout. Keeping the pipe OPEN
while waiting matters - if you close stdin immediately the server begins
shutting down and may never flush the responses.

Proves the full path:  smoke.py -> guardrails proxy -> filesystem server

Usage:
    python3 scripts/smoke.py [path-to-binary]
"""

import json
import os
import subprocess
import sys
import tempfile
import threading

BIN = (
    sys.argv[1]
    if len(sys.argv) > 1
    else "src/McpGuardrails.Cli/bin/Debug/net10.0/McpGuardrails.Cli"
)

# tempfile.gettempdir() honours TMPDIR/TEMP and falls back sanely per platform,
# rather than hardcoding a world-writable "/tmp".
SANDBOX = os.environ.get(
    "GUARDRAILS_SANDBOX",
    os.path.join(tempfile.gettempdir(), "guardrails-sandbox"),
).rstrip("/")

PROBE = f"{SANDBOX}/smoke-probe.txt"
AUDIT = f"{SANDBOX}/audit.jsonl"
POLICY_AUDIT = f"{SANDBOX}/audit-policy.jsonl"
POLICY_FILE = f"{SANDBOX}/smoke-policy.yaml"
CONTENT = "written through the guardrails proxy"

# A path the sandbox rules must refuse. Never actually written: the point is
# that the proxy stops the call before the filesystem server ever sees it.
ESCAPE = os.path.join(tempfile.gettempdir(), "guardrails-escape.txt")

# Exercises all three matcher kinds against a real downstream server: a tool
# glob, an argument predicate, and the annotations the server advertises.
# First match wins, so the order is the policy.
POLICY = f"""
rules:
  - name: allow-reads
    match:
      tool: fs__read_*
    decision: allow

  - name: allow-sandbox-writes
    match:
      tool: fs__write_*
      args:
        - path: $.path
          prefix: {SANDBOX}/
    decision: allow

  - name: deny-sandbox-escape
    match:
      tool: fs__write_*
    decision: deny
    message: Write inside the sandbox instead.

  - name: deny-destructive
    match:
      annotations:
        destructiveHint: true
    decision: deny
    message: Destructive tools are disabled here.
"""


def request(rid: int, method: str, params: dict | None = None) -> dict:
    msg: dict = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def call(rid: int, name: str, args: dict) -> dict:
    return request(rid, "tools/call", {"name": name, "arguments": args})


# Each entry: (request, human label, predicate over the `result` object)
CHECKS: list[tuple[dict, str, object]] = [
    (
        request(1, "tools/list"),
        "proxy advertises namespaced downstream tools",
        lambda r: any(t["name"] == "fs__write_file" for t in r.get("tools", [])),
    ),
    (
        call(2, "fs__write_file", {"path": PROBE, "content": CONTENT}),
        "write_file forwarded downstream",
        lambda r: not r.get("isError"),
    ),
    (
        call(3, "fs__read_text_file", {"path": PROBE}),
        "read_text_file returns what we wrote",
        lambda r: CONTENT in json.dumps(r.get("content", [])),
    ),
    (
        call(4, "fs__does_not_exist", {}),
        "unknown tool -> tool error, not a protocol error",
        lambda r: bool(r.get("isError")),
    ),
]


def denied_with(result: dict, fragment: str) -> bool:
    """A policy refusal is a tool error whose text the model is meant to read."""
    return bool(result.get("isError")) and fragment in json.dumps(
        result.get("content", [])
    )


# Each entry: (request, human label, predicate over the `result` object)
POLICY_CHECKS: list[tuple[dict, str, object]] = [
    (
        call(1, "fs__write_file", {"path": PROBE, "content": CONTENT}),
        "glob + argument predicate allows a write inside the sandbox",
        lambda r: not r.get("isError"),
    ),
    (
        call(2, "fs__write_file", {"path": ESCAPE, "content": CONTENT}),
        "argument predicate denies the same tool outside the sandbox",
        lambda r: denied_with(r, "Write inside the sandbox instead."),
    ),
    (
        call(3, "fs__move_file", {"source": PROBE, "destination": ESCAPE}),
        "annotation rule denies a destructive tool nobody named",
        lambda r: denied_with(r, "Destructive tools are disabled here."),
    ),
    (
        call(4, "fs__read_text_file", {"path": PROBE}),
        "a read is still allowed by the glob rule above the denials",
        lambda r: CONTENT in json.dumps(r.get("content", [])),
    ),
]


def main() -> int:
    try:
        os.makedirs(SANDBOX, exist_ok=True)
    except OSError as exc:
        print(f"cannot create sandbox {SANDBOX}: {exc}", file=sys.stderr)
        return 1

    # Remove any probe left by a previous run so a stale file cannot make the
    # read check pass without the write actually working.
    try:
        os.remove(PROBE)
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"cannot clear probe file {PROBE}: {exc}", file=sys.stderr)
        return 1

    for stale in (AUDIT, POLICY_AUDIT, ESCAPE):
        try:
            os.remove(stale)
        except FileNotFoundError:
            pass
        except OSError as exc:
            print(f"cannot clear {stale}: {exc}", file=sys.stderr)
            return 1

    try:
        with open(POLICY_FILE, "w", encoding="utf-8") as handle:
            handle.write(POLICY)
    except OSError as exc:
        print(f"cannot write policy {POLICY_FILE}: {exc}", file=sys.stderr)
        return 1

    # Phase 1: pure passthrough. GUARDRAILS_POLICY points at a file that does not
    # exist on purpose - without it the proxy would pick up the developer's own
    # ~/.mcp-guardrails/policy.yaml and this run would not be reproducible.
    print("--- passthrough ---")
    failures, stderr_lines = run_session(
        CHECKS,
        {
            "GUARDRAILS_AUDIT": AUDIT,
            "GUARDRAILS_POLICY": f"{SANDBOX}/no-such-policy.yaml",
        },
    )
    failures += check_audit_log()

    # Phase 2: the same server behind a policy that denies by glob, by argument
    # and by annotation.
    print("\n--- policy enforcement ---")
    policy_failures, policy_stderr = run_session(
        POLICY_CHECKS,
        {"GUARDRAILS_AUDIT": POLICY_AUDIT, "GUARDRAILS_POLICY": POLICY_FILE},
    )
    failures += policy_failures
    failures += check_policy_audit_log()

    # A denied call must never reach the filesystem server.
    escaped = os.path.exists(ESCAPE)
    print(f"{'FAIL' if escaped else 'PASS'}  denied write never touched the disk")
    failures += 1 if escaped else 0

    if failures:
        print("\n--- server stderr (last 30) ---", file=sys.stderr)
        sys.stderr.writelines((stderr_lines + policy_stderr)[-30:])

    print("\nFAILED" if failures else "\nALL OK")
    return 1 if failures else 0


def run_session(
    checks: list[tuple[dict, str, object]], extra_env: dict[str, str]
) -> tuple[int, list[str]]:
    """Drive one proxy process through a list of checks."""
    proc = subprocess.Popen(
        [BIN],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env={**os.environ, "GUARDRAILS_SANDBOX": SANDBOX, **extra_env},
    )

    # Popen's pipe attributes are Optional[IO] to the type checker; we passed
    # PIPE for all three, so narrow them once here.
    stdin, stdout, stderr = proc.stdin, proc.stdout, proc.stderr
    if stdin is None or stdout is None or stderr is None:
        raise RuntimeError("failed to open pipes to the server process")

    # Drain stderr on a background thread so a chatty server can't fill the pipe
    # buffer and deadlock us.
    stderr_lines: list[str] = []
    threading.Thread(target=lambda: stderr_lines.extend(stderr), daemon=True).start()

    failures = 0
    try:
        for req, label, predicate in checks:
            stdin.write(json.dumps(req) + "\n")
            stdin.flush()

            line = stdout.readline()
            if not line:
                print(f"FAIL  {label}: stdout closed early")
                failures += 1
                break

            try:
                msg = json.loads(line)
            except json.JSONDecodeError as exc:
                # Non-JSON on stdout almost always means something logged there
                # and corrupted the JSON-RPC stream - the classic stdio bug.
                print(f"FAIL  {label}: non-JSON on stdout ({exc}): {line[:200]}")
                failures += 1
                continue

            result = msg.get("result")
            ok = result is not None and bool(predicate(result))  # type: ignore[operator]
            print(f"{'PASS' if ok else 'FAIL'}  {label}")
            if not ok:
                failures += 1
                print(json.dumps(msg, indent=2)[:700])
    finally:
        stdin.close()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()

    return failures, stderr_lines


def check_policy_audit_log() -> int:
    """The audit log must name the rule that refused each call."""
    try:
        with open(POLICY_AUDIT, encoding="utf-8") as handle:
            lines = [json.loads(line) for line in handle if line.strip()]
    except FileNotFoundError:
        print("FAIL  policy audit log was not created")
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL  policy audit log unreadable: {exc}")
        return 1

    failures = 0

    def expect(condition: bool, label: str) -> None:
        nonlocal failures
        print(f"{'PASS' if condition else 'FAIL'}  {label}")
        if not condition:
            failures += 1

    denials = [entry for entry in lines if entry.get("decision") == "deny"]
    rules = {entry.get("rule") for entry in denials}

    expect(len(denials) == 2, f"audit records both denials (got {len(denials)})")
    expect(
        rules == {"deny-sandbox-escape", "deny-destructive"},
        f"audit names the rule that refused each call (got {sorted(rules)})",
    )
    expect(
        all(entry.get("is_error") for entry in denials),
        "denied calls are flagged as errors",
    )

    return failures


def check_audit_log() -> int:
    """Verify the audit filter recorded every call, including the rejected one."""
    try:
        with open(AUDIT, encoding="utf-8") as handle:
            lines = [json.loads(line) for line in handle if line.strip()]
    except FileNotFoundError:
        print("FAIL  audit log was not created")
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL  audit log unreadable: {exc}")
        return 1

    failures = 0

    def expect(condition: bool, label: str) -> None:
        nonlocal failures
        print(f"{'PASS' if condition else 'FAIL'}  {label}")
        if not condition:
            failures += 1

    by_tool = {entry.get("tool"): entry for entry in lines}

    expect(len(lines) == 3, f"audit log has one line per tools/call (got {len(lines)})")

    write = by_tool.get("fs__write_file")
    expect(write is not None, "audit records the forwarded write_file call")
    if write:
        expect(write.get("server") == "fs", "audit resolves the downstream server")
        expect(
            write.get("downstream_tool") == "write_file",
            "audit records the un-namespaced tool",
        )
        expect(not write.get("is_error"), "successful call is not flagged as an error")
        expect(
            isinstance(write.get("duration_ms"), (int, float)),
            "audit records a duration",
        )
        expect(
            write.get("arguments", {}).get("path") == PROBE,
            "audit captures call arguments",
        )

    # The whole point of putting audit outermost: it must see rejected calls too.
    unknown = by_tool.get("fs__does_not_exist")
    expect(unknown is not None, "audit records the REJECTED call, not just successes")
    if unknown:
        expect(bool(unknown.get("is_error")), "rejected call is flagged as an error")
        expect(
            unknown.get("server") is None, "unresolved call has no downstream server"
        )

    return failures


if __name__ == "__main__":
    sys.exit(main())
