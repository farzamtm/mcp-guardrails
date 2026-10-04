#!/usr/bin/env python3
"""
A tiny stdio MCP server for scripts/smoke.py, with no dependencies.

It exists to make things observable that a real server keeps to itself. Its one
interesting tool, env_names, reports which environment variables the server
process can see, which is how the smoke test proves that environment isolation
keeps the proxy's secrets out of a downstream server.

Speaks just enough of the protocol for the proxy: initialize, tools/list and
tools/call, as newline-delimited JSON-RPC on stdin/stdout.

Usage:
    python3 scripts/fixture_server.py
"""

import json
import os
import sys

TOOLS = [
    {
        "name": "env_names",
        "description": "Lists the environment variable names this server can see.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "echo",
        "description": "Echoes a message back.",
        "inputSchema": {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"],
        },
        "annotations": {"readOnlyHint": True},
    },
]


def call_tool(name: str, arguments: dict) -> dict:
    if name == "env_names":
        text = "\n".join(sorted(os.environ))
    elif name == "echo":
        text = f"echo: {arguments.get('message', '')}"
    else:
        return {
            "content": [{"type": "text", "text": f"unknown tool {name}"}],
            "isError": True,
        }
    return {"content": [{"type": "text", "text": text}]}


def handle(message: dict) -> dict | None:
    method = message.get("method")
    params = message.get("params") or {}

    if method == "initialize":
        result = {
            # Echo the client's version back: the fixture has no opinion about
            # protocol revisions, and the proxy's SDK picks one it supports.
            "protocolVersion": params.get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "guardrails-fixture", "version": "0"},
        }
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        result = call_tool(params.get("name", ""), params.get("arguments") or {})
    elif method == "ping":
        result = {}
    elif "id" not in message:
        # A notification (initialized, cancelled): nothing to answer.
        return None
    else:
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {"code": -32601, "message": f"method not found: {method}"},
        }

    return {"jsonrpc": "2.0", "id": message.get("id"), "result": result}


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        reply = handle(json.loads(line))
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
