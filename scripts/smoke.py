#!/usr/bin/env python3
"""
Minimal MCP stdio driver, for smoke-testing the proxy without Claude Desktop.

Deliberately dependency-free: it speaks newline-delimited JSON-RPC straight at
the child process's stdin and reads replies off stdout. Keeping the pipe OPEN
while waiting matters - if you close stdin immediately the server begins
shutting down and may never flush the responses.

Proves the full path:  smoke.py -> guardrails proxy -> filesystem server

The last phase drives the same proxy over Streamable HTTP instead (stdlib
urllib, still no dependencies), to prove both transports run one pipeline.

Usage:
    python3 scripts/smoke.py [path-to-binary]
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

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

# Sent on the initialize handshake. Only the approval phases handshake at all;
# everything else drives the proxy without one, which is what the earlier phases
# have always done.
PROTOCOL_VERSION = "2025-06-18"

PROBE = f"{SANDBOX}/smoke-probe.txt"
AUDIT = f"{SANDBOX}/audit.jsonl"
POLICY_AUDIT = f"{SANDBOX}/audit-policy.jsonl"
POLICY_FILE = f"{SANDBOX}/smoke-policy.yaml"
BUDGET_AUDIT = f"{SANDBOX}/audit-budget.jsonl"
BUDGET_FILE = f"{SANDBOX}/smoke-budget.yaml"
BUDGET_PROBE = f"{SANDBOX}/smoke-budget-1.txt"
BUDGET_OVER = f"{SANDBOX}/smoke-budget-2.txt"
APPROVAL_AUDIT = f"{SANDBOX}/audit-approval.jsonl"
APPROVAL_FILE = f"{SANDBOX}/smoke-approval.yaml"
APPROVAL_PROBE = f"{SANDBOX}/smoke-approved.txt"
APPROVAL_REFUSED = f"{SANDBOX}/smoke-unapproved.txt"
HTTP_AUDIT = f"{SANDBOX}/audit-http.jsonl"
HTTP_FILE = f"{SANDBOX}/smoke-http.yaml"
HTTP_PROBE = f"{SANDBOX}/smoke-http.txt"
HTTP_OVER = f"{SANDBOX}/smoke-http-over.txt"
HTTP_UNAPPROVED = f"{SANDBOX}/smoke-http-unapproved.txt"
CONTENT = "written through the guardrails proxy"

# Long enough to pass the proxy's minimum. Not a secret: it guards a listener on
# an ephemeral loopback port for the few seconds this phase runs.
HTTP_TOKEN = "smoke-test-token-0123456789"

# A path the sandbox rules must refuse. Never actually written: the point is
# that the proxy stops the call before the filesystem server ever sees it.
ESCAPE = os.path.join(tempfile.gettempdir(), "guardrails-escape.txt")

# A pattern that backtracks catastrophically, plus an input that provokes it.
# Used to prove the proxy refuses a call whose guardrail it could not finish
# checking, rather than waving it through.
STALLING_PATTERN = "^(a+)+$"
STALLING_CONTENT = ("a" * 40) + "!"

# Exercises all three matcher kinds against a real downstream server: a tool
# glob, an argument predicate, and the annotations the server advertises.
# First match wins, so the order is the policy.
POLICY = f"""
rules:
  - name: allow-reads
    match:
      tool: fs__read_*
    decision: allow

  # Above the allow rules on purpose: it has to be reached before the write is
  # permitted, which is exactly the position a real scanning rule would take.
  - name: deny-unscannable
    match:
      tool: fs__write_*
      args:
        - path: $.content
          matches: "{STALLING_PATTERN}"
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

# A budget small enough to run out inside one session, with costs that differ by
# tool - which is the whole point of weighting. Two writes cost 4 against a cap
# of 3, so the second one cannot happen; reads are free and keep working after
# the budget is gone.
BUDGET_POLICY = """
budgets:
  session:
    max_cost: 3

rules:
  - name: reads-are-free
    match:
      tool: fs__read_*
    decision: allow
    cost: 0

  - name: writes-cost
    match:
      tool: fs__write_*
    decision: allow
    cost: 2
"""

# Every write goes to a human. The timeout is deliberately tiny: one phase below
# never answers at all, and CI should not spend five minutes proving it.
APPROVAL_POLICY = """
rules:
  - name: allow-reads
    match:
      tool: fs__read_*
    decision: allow

  - name: approve-writes
    match:
      tool: fs__write_*
    decision: require_approval
    approval:
      timeout_s: 2
      prompt: Allow the agent to write a file in the sandbox?
"""


# The same guardrails, served over Streamable HTTP. One policy exercising every
# gate at once, because the point of this phase is not the gates themselves -
# the stdio phases prove those - but that HTTP runs the identical pipeline.
#
# max_calls: 3 is reached across separate HTTP requests: in stateless mode every
# request is a fresh server, so a cap that still bites proves the budget lives in
# the process, not in a session that no longer exists.
HTTP_POLICY = f"""
budgets:
  session:
    max_calls: 3

rules:
  - name: allow-reads
    match:
      tool: fs__read_*
    decision: allow

  - name: approve-unapproved
    match:
      tool: fs__write_*
      args:
        - path: $.path
          eq: "{HTTP_UNAPPROVED}"
    decision: require_approval
    approval:
      timeout_s: 30

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
    (
        call(
            5,
            "fs__write_file",
            {"path": PROBE, "content": STALLING_CONTENT},
        ),
        "a guardrail that cannot be evaluated denies instead of falling through",
        # The rule it stalls says 'allow', and the write is inside the sandbox,
        # so every path other than fail-closed ends in the call being forwarded.
        lambda r: denied_with(r, "could not be evaluated"),
    ),
]


# The budget is per session, so these run in order against one proxy process and
# each check depends on the one before it. That is the behaviour under test.
BUDGET_CHECKS: list[tuple[dict, str, object]] = [
    (
        call(1, "fs__write_file", {"path": BUDGET_PROBE, "content": CONTENT}),
        "the first write fits the budget (2 of 3)",
        lambda r: not r.get("isError"),
    ),
    (
        call(2, "fs__write_file", {"path": BUDGET_OVER, "content": CONTENT}),
        "the second write would exceed it and is refused",
        lambda r: denied_with(r, "Blocked by guardrails budget 'session.max_cost'"),
    ),
    (
        call(3, "fs__read_text_file", {"path": BUDGET_PROBE}),
        "a cost-0 read still works after the budget is spent",
        lambda r: CONTENT in json.dumps(r.get("content", [])),
    ),
]


# Four sessions, one per answer a human can give - including not being there at
# all. Each runs against its own proxy process because the answer is fixed for
# the session.
APPROVED_CHECKS: list[tuple[dict, str, object]] = [
    (
        call(1, "fs__write_file", {"path": APPROVAL_PROBE, "content": CONTENT}),
        "a human approves and the write goes through",
        lambda r: not r.get("isError"),
    ),
    (
        call(2, "fs__read_text_file", {"path": APPROVAL_PROBE}),
        "the approved write really reached the server",
        lambda r: CONTENT in json.dumps(r.get("content", [])),
    ),
]

DECLINED_CHECKS: list[tuple[dict, str, object]] = [
    (
        call(1, "fs__write_file", {"path": APPROVAL_REFUSED, "content": CONTENT}),
        "a human declines and the call is refused",
        lambda r: denied_with(r, "declined it"),
    ),
]

TIMEOUT_CHECKS: list[tuple[dict, str, object]] = [
    (
        call(1, "fs__write_file", {"path": APPROVAL_REFUSED, "content": CONTENT}),
        "nobody answers and silence is refusal",
        lambda r: denied_with(r, "nobody answered"),
    ),
]

NO_APPROVER_CHECKS: list[tuple[dict, str, object]] = [
    (
        call(1, "fs__write_file", {"path": APPROVAL_REFUSED, "content": CONTENT}),
        "a client that cannot ask anyone is refused, and told why",
        lambda r: denied_with(r, "cannot ask anyone"),
    ),
]


# Run in order against one HTTP proxy process; the budget check depends on the
# three successful calls before it.
HTTP_CHECKS: list[tuple[dict, str, object]] = [
    (
        request(1, "tools/list"),
        "HTTP: proxy advertises namespaced downstream tools",
        lambda r: any(t["name"] == "fs__write_file" for t in r.get("tools", [])),
    ),
    (
        call(2, "fs__write_file", {"path": HTTP_PROBE, "content": CONTENT}),
        "HTTP: an allowed write is forwarded downstream",
        lambda r: not r.get("isError"),
    ),
    (
        call(3, "fs__write_file", {"path": ESCAPE, "content": CONTENT}),
        "HTTP: the policy denies a write outside the sandbox",
        lambda r: denied_with(r, "Write inside the sandbox instead."),
    ),
    (
        call(4, "fs__write_file", {"path": HTTP_UNAPPROVED, "content": CONTENT}),
        "HTTP: require_approval fails closed - stateless HTTP cannot ask anyone",
        lambda r: denied_with(r, "stateless"),
    ),
    (
        call(5, "fs__read_text_file", {"path": HTTP_PROBE}),
        "HTTP: a read returns what the write stored",
        lambda r: CONTENT in json.dumps(r.get("content", [])),
    ),
    (
        call(6, "fs__write_file", {"path": HTTP_PROBE, "content": CONTENT}),
        "HTTP: the third forwarded call still fits the budget",
        lambda r: not r.get("isError"),
    ),
    (
        call(7, "fs__write_file", {"path": HTTP_OVER, "content": CONTENT}),
        "HTTP: the budget spans stateless requests and refuses the fourth",
        lambda r: denied_with(r, "session.max_calls"),
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

    for stale in (
        AUDIT,
        POLICY_AUDIT,
        BUDGET_AUDIT,
        BUDGET_PROBE,
        BUDGET_OVER,
        APPROVAL_AUDIT,
        APPROVAL_PROBE,
        APPROVAL_REFUSED,
        HTTP_AUDIT,
        HTTP_PROBE,
        HTTP_OVER,
        HTTP_UNAPPROVED,
        ESCAPE,
    ):
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
        with open(BUDGET_FILE, "w", encoding="utf-8") as handle:
            handle.write(BUDGET_POLICY)
        with open(APPROVAL_FILE, "w", encoding="utf-8") as handle:
            handle.write(APPROVAL_POLICY)
        with open(HTTP_FILE, "w", encoding="utf-8") as handle:
            handle.write(HTTP_POLICY)
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

    # Phase 3: a session budget running out mid-session, with per-rule costs.
    print("\n--- budget enforcement ---")
    budget_failures, budget_stderr = run_session(
        BUDGET_CHECKS,
        {"GUARDRAILS_AUDIT": BUDGET_AUDIT, "GUARDRAILS_POLICY": BUDGET_FILE},
    )
    failures += budget_failures
    failures += check_budget_audit_log()

    # Phase 4: a human in the loop. One session per answer, because the fake
    # human's answer is fixed for a session - and the last one is not there at
    # all, which is the case most operators will actually hit.
    print("\n--- approval ---")
    approval_env = {
        "GUARDRAILS_AUDIT": APPROVAL_AUDIT,
        "GUARDRAILS_POLICY": APPROVAL_FILE,
    }
    approval_stderr: list[str] = []

    for checks, answer, handshake in (
        (APPROVED_CHECKS, "approve", True),
        (DECLINED_CHECKS, "decline", True),
        (TIMEOUT_CHECKS, "ignore", True),
        (NO_APPROVER_CHECKS, "approve", False),
    ):
        session_failures, session_stderr = run_session(
            checks,
            approval_env,
            handshake=handshake,
            elicit=answer,
        )
        failures += session_failures
        approval_stderr += session_stderr

    failures += check_approval_audit_log()

    # Phase 5: the same pipeline over Streamable HTTP.
    print("\n--- streamable http ---")
    http_failures, http_stderr = run_http_session(
        HTTP_CHECKS,
        {
            "GUARDRAILS_AUDIT": HTTP_AUDIT,
            "GUARDRAILS_POLICY": HTTP_FILE,
            "GUARDRAILS_HTTP_TOKEN": HTTP_TOKEN,
        },
    )
    failures += http_failures
    failures += check_http_audit_log()

    for path, label in (
        (HTTP_UNAPPROVED, "HTTP: the unapprovable write never reached the disk"),
        (HTTP_OVER, "HTTP: the over-budget write never happened"),
    ):
        exists = os.path.exists(path)
        print(f"{'FAIL' if exists else 'PASS'}  {label}")
        failures += 1 if exists else 0

    unapproved = os.path.exists(APPROVAL_REFUSED)
    print(f"{'FAIL' if unapproved else 'PASS'}  no unapproved write reached the disk")
    failures += 1 if unapproved else 0

    # A denied call must never reach the filesystem server.
    escaped = os.path.exists(ESCAPE)
    print(f"{'FAIL' if escaped else 'PASS'}  denied write never touched the disk")
    failures += 1 if escaped else 0

    overspent = os.path.exists(BUDGET_OVER)
    print(f"{'FAIL' if overspent else 'PASS'}  the over-budget write never happened")
    failures += 1 if overspent else 0

    if failures:
        print("\n--- server stderr (last 30) ---", file=sys.stderr)
        sys.stderr.writelines(
            (
                stderr_lines
                + policy_stderr
                + budget_stderr
                + approval_stderr
                + http_stderr
            )[-30:]
        )

    print("\nFAILED" if failures else "\nALL OK")
    return 1 if failures else 0


def run_session(
    checks: list[tuple[dict, str, object]],
    extra_env: dict[str, str],
    *,
    handshake: bool = False,
    elicit: str = "approve",
) -> tuple[int, list[str]]:
    """Drive one proxy process through a list of checks.

    handshake sends initialize declaring the elicitation capability, which is
    what makes the proxy willing to ask this client for approval. Without it the
    proxy has nobody to ask, which is itself a case worth testing.

    elicit decides how this fake human answers: approve, decline, or ignore (say
    nothing at all and let the approval time out).
    """
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

    def send(message: dict) -> None:
        stdin.write(json.dumps(message) + "\n")
        stdin.flush()

    def answer_elicitation(message: dict) -> None:
        """Play the human at the client."""
        if elicit == "ignore":
            # Say nothing at all. The proxy's own deadline has to be what ends
            # the wait, which is the only way to test it honestly.
            return

        result = (
            {"action": "accept", "content": {"approve": True}}
            if elicit == "approve"
            else {"action": "decline"}
        )
        send({"jsonrpc": "2.0", "id": message["id"], "result": result})

    def read_reply(rid: int, label: str) -> dict | None:
        """Read until the reply to rid arrives, serving requests met on the way.

        Approval inverts the usual direction: while the client waits for a tool
        result, the SERVER asks the client a question. A driver that assumed one
        line in per line out would deadlock on it.
        """
        while True:
            line = stdout.readline()
            if not line:
                print(f"FAIL  {label}: stdout closed early")
                return None

            try:
                msg = json.loads(line)
            except json.JSONDecodeError as exc:
                # Non-JSON on stdout almost always means something logged there
                # and corrupted the JSON-RPC stream - the classic stdio bug.
                print(f"FAIL  {label}: non-JSON on stdout ({exc}): {line[:200]}")
                return None

            if msg.get("method") == "elicitation/create":
                answer_elicitation(msg)
                continue

            # Any other server-initiated traffic (notifications, requests we do
            # not implement) is not what we are waiting for.
            if msg.get("id") != rid:
                continue

            return msg

    try:
        if handshake:
            # Without this the proxy has no client capabilities to inspect, so
            # it has nobody to ask and every require_approval rule denies.
            send(
                request(
                    0,
                    "initialize",
                    {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {"elicitation": {}},
                        "clientInfo": {"name": "smoke.py", "version": "0"},
                    },
                )
            )
            if read_reply(0, "initialize") is None:
                return 1, stderr_lines
            send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        for req, label, predicate in checks:
            send(req)

            msg = read_reply(req["id"], label)
            if msg is None:
                failures += 1
                break

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


def run_http_session(
    checks: list[tuple[dict, str, object]],
    extra_env: dict[str, str],
) -> tuple[int, list[str]]:
    """Drive one proxy process serving Streamable HTTP through a list of checks.

    Port 0 lets the OS pick a free port, so parallel CI jobs cannot collide; the
    proxy logs the address it actually bound, and that line is how we find it.
    """
    proc = subprocess.Popen(
        [BIN, "--transport", "http", "--port", "0"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env={**os.environ, "GUARDRAILS_SANDBOX": SANDBOX, **extra_env},
    )
    stderr = proc.stderr
    if stderr is None:
        raise RuntimeError("failed to open the server's stderr")

    stderr_lines: list[str] = []
    found = threading.Event()
    endpoint: list[str] = []

    def drain() -> None:
        pattern = re.compile(r"at (http://\S+/mcp)")
        for line in stderr:
            stderr_lines.append(line)
            match = pattern.search(line)
            if match and not endpoint:
                endpoint.append(match.group(1))
                found.set()

    threading.Thread(target=drain, daemon=True).start()

    failures = 0

    def expect(condition: bool, label: str) -> None:
        nonlocal failures
        print(f"{'PASS' if condition else 'FAIL'}  {label}")
        if not condition:
            failures += 1

    try:
        # Generous: the downstream server is fetched by npx before we listen.
        if not found.wait(timeout=120):
            print("FAIL  HTTP: the proxy never reported a listening address")
            return 1, stderr_lines

        url = endpoint[0]
        expect(
            url.startswith("http://127.0.0.1:"),
            f"HTTP: binds loopback by default ({url})",
        )

        status, _ = http_post(url, request(100, "tools/list"), token=None)
        expect(status == 401, f"HTTP: no bearer token -> 401 (got {status})")

        status, _ = http_post(url, request(101, "tools/list"), token="wrong-token")
        expect(status == 401, f"HTTP: wrong bearer token -> 401 (got {status})")

        # What a browser sends when someone else's page targets the loopback
        # port, e.g. after DNS rebinding. The right token must not rescue it.
        status, _ = http_post(
            url,
            request(102, "tools/list"),
            token=HTTP_TOKEN,
            origin="https://attacker.example",
        )
        expect(status == 403, f"HTTP: foreign Origin -> 403 (got {status})")

        for req, label, predicate in checks:
            started = time.monotonic()
            status, msg = http_post(url, req, token=HTTP_TOKEN)
            elapsed = time.monotonic() - started

            result = msg.get("result") if msg else None
            ok = status == 200 and result is not None
            ok = ok and bool(predicate(result))  # type: ignore[operator]
            # A refusal that only arrives when the 30s approval deadline expires
            # would pass the predicate, but it is the hang this design rules out.
            ok = ok and elapsed < 10
            print(f"{'PASS' if ok else 'FAIL'}  {label}")
            if not ok:
                failures += 1
                print(f"  status={status} elapsed={elapsed:.1f}s")
                print(json.dumps(msg, indent=2)[:700])

        # The audit sink flushes in the background. On Windows terminate() is a
        # hard kill with no graceful shutdown to drain it, so wait for the lines
        # rather than racing the flush.
        calls = sum(1 for req, _, _ in checks if req["method"] == "tools/call")
        wait_for_lines(extra_env["GUARDRAILS_AUDIT"], calls, timeout=10)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()

    return failures, stderr_lines


def wait_for_lines(path: str, count: int, *, timeout: float) -> None:
    """Return once path holds at least count lines, or when timeout runs out."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(path, encoding="utf-8") as handle:
                if sum(1 for line in handle if line.strip()) >= count:
                    return
        except FileNotFoundError:
            pass
        time.sleep(0.1)


def http_post(
    url: str,
    message: dict,
    *,
    token: str | None,
    origin: str | None = None,
) -> tuple[int, dict | None]:
    """POST one JSON-RPC message; return the status and the matching reply.

    Streamable HTTP may answer with plain JSON or with a short SSE stream, so
    both are accepted - a client that only handled one would be testing the SDK's
    choice, not the proxy.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if origin is not None:
        headers["Origin"] = origin

    req = urllib.request.Request(
        url,
        data=json.dumps(message).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            status = response.status
            content_type = response.headers.get("Content-Type", "")
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, None

    if content_type.startswith("application/json"):
        candidates = [body]
    else:
        candidates = [
            line[len("data:") :].strip()
            for line in body.splitlines()
            if line.startswith("data:")
        ]

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if parsed.get("id") == message.get("id"):
            return status, parsed

    return status, None


def check_http_audit_log() -> int:
    """HTTP calls must be audited exactly like stdio ones."""
    try:
        with open(HTTP_AUDIT, encoding="utf-8") as handle:
            lines = [json.loads(line) for line in handle if line.strip()]
    except FileNotFoundError:
        print("FAIL  HTTP audit log was not created")
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL  HTTP audit log unreadable: {exc}")
        return 1

    failures = 0

    def expect(condition: bool, label: str) -> None:
        nonlocal failures
        print(f"{'PASS' if condition else 'FAIL'}  {label}")
        if not condition:
            failures += 1

    # Six tool calls; the HTTP requests refused for auth or origin never reached
    # the MCP server, so they are not tool calls and must not appear.
    expect(
        len(lines) == 6,
        "HTTP: one audit line per tools/call, none for refused requests "
        f"(got {len(lines)})",
    )
    rules = {entry.get("rule") for entry in lines if entry.get("decision") == "deny"}
    expect(
        rules == {"deny-sandbox-escape", "approve-unapproved", "session.max_calls"},
        "HTTP: audit names the policy, approval and budget refusals "
        f"(got {sorted(r or '' for r in rules)})",
    )
    expect(
        any(entry.get("approval") == "unavailable" for entry in lines),
        "HTTP: the unapprovable call is logged as approval 'unavailable'",
    )

    return failures


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

    expect(len(denials) == 3, f"audit records every denial (got {len(denials)})")
    expect(
        rules == {"deny-sandbox-escape", "deny-destructive", "deny-unscannable"},
        f"audit names the rule that refused each call (got {sorted(rules)})",
    )
    # The refusal that matters most to have in the log: a guardrail the proxy
    # could not finish checking is invisible in the call itself, so the record
    # naming the rule is the only trace an operator gets.
    expect(
        any(
            entry.get("rule") == "deny-unscannable"
            and "could not be evaluated" in (entry.get("decision_reason") or "")
            for entry in denials
        ),
        "audit explains the undecidable denial rather than logging a bare deny",
    )
    expect(
        all(entry.get("is_error") for entry in denials),
        "denied calls are flagged as errors",
    )

    return failures


def check_approval_audit_log() -> int:
    """Every answer a human can give must be distinguishable in the log."""
    try:
        with open(APPROVAL_AUDIT, encoding="utf-8") as handle:
            lines = [json.loads(line) for line in handle if line.strip()]
    except FileNotFoundError:
        print("FAIL  approval audit log was not created")
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL  approval audit log unreadable: {exc}")
        return 1

    failures = 0

    def expect(condition: bool, label: str) -> None:
        nonlocal failures
        print(f"{'PASS' if condition else 'FAIL'}  {label}")
        if not condition:
            failures += 1

    outcomes = {entry.get("approval") for entry in lines if entry.get("approval")}

    expect(
        outcomes == {"approved", "declined", "timed_out", "unavailable"},
        f"audit distinguishes all four approval outcomes (got {sorted(outcomes)})",
    )
    # The distinction the verdict alone destroys: an allowed call that a person
    # actually looked at.
    expect(
        any(
            entry.get("approval") == "approved" and entry.get("decision") == "allow"
            for entry in lines
        ),
        "an approved call is logged as allowed AND as approved",
    )
    expect(
        all(
            entry.get("decision") == "deny"
            for entry in lines
            if entry.get("approval") in {"declined", "timed_out", "unavailable"}
        ),
        "every unapproved call is logged as denied",
    )

    return failures


def check_budget_audit_log() -> int:
    """A budget refusal must be as traceable as a policy one."""
    try:
        with open(BUDGET_AUDIT, encoding="utf-8") as handle:
            lines = [json.loads(line) for line in handle if line.strip()]
    except FileNotFoundError:
        print("FAIL  budget audit log was not created")
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL  budget audit log unreadable: {exc}")
        return 1

    failures = 0

    def expect(condition: bool, label: str) -> None:
        nonlocal failures
        print(f"{'PASS' if condition else 'FAIL'}  {label}")
        if not condition:
            failures += 1

    denials = [entry for entry in lines if entry.get("decision") == "deny"]

    expect(len(denials) == 1, f"exactly one call was refused (got {len(denials)})")
    expect(
        any(entry.get("rule") == "session.max_cost" for entry in denials),
        "audit names the cap that refused the call, not a policy rule",
    )
    # Which cap, and how much was left: without the numbers an operator cannot
    # tell a budget that was too tight from an agent that ran away.
    expect(
        any(
            "spent 2 of its 3" in (entry.get("decision_reason") or "")
            for entry in denials
        ),
        "audit records what was spent and what the cap was",
    )
    expect(
        len(lines) == 3,
        f"every call is logged, refused or not (got {len(lines)})",
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
