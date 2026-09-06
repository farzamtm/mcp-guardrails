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

BIN = sys.argv[1] if len(sys.argv) > 1 else \
    "src/McpGuardrails.Cli/bin/Debug/net10.0/McpGuardrails.Cli"

# tempfile.gettempdir() honours TMPDIR/TEMP and falls back sanely per platform,
# rather than hardcoding a world-writable "/tmp".
SANDBOX = os.environ.get(
    "GUARDRAILS_SANDBOX",
    os.path.join(tempfile.gettempdir(), "guardrails-sandbox"),
).rstrip("/")

PROBE = f"{SANDBOX}/smoke-probe.txt"
CONTENT = "written through the guardrails proxy"


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

    proc = subprocess.Popen(
        [BIN],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
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
        for req, label, predicate in CHECKS:
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

    if failures:
        print("\n--- server stderr (last 30) ---", file=sys.stderr)
        sys.stderr.writelines(stderr_lines[-30:])

    print("\nFAILED" if failures else "\nALL OK")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
