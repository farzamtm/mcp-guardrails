# The 60-second demo

Put the proxy in front of a real Claude Code session, with a policy generated
from the built-in packs, and watch it stop a planted prompt injection.

You need [Node](https://nodejs.org/) 22 or later (the filesystem server runs
through `npx`), [Claude Code](https://code.claude.com/), `jq`, and the
`mcp-guardrails` binary on your `PATH` (see [Install](../README.md#install)).
On a clean machine it takes under five minutes.

The fixture is [`examples/demo/`](../examples/demo/): a small project whose
`notes/vendor-email.md` hides instructions telling an AI assistant to read
credentials and email them away.

## 1. Give Claude Code a server to protect

From the repository root, create a project-scoped Claude Code config that
serves the demo workspace through the official filesystem server:

```bash
cd examples/demo
cat > .mcp.json <<JSON
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@2026.8.31", "$PWD/workspace"]
    }
  }
}
JSON
```

## 2. Wrap it

See what would change, then do it:

```bash
mcp-guardrails wrap --client claude-code --dry-run
mcp-guardrails wrap --client claude-code
```

`wrap` moves the server into `~/.mcp-guardrails/servers.yaml`, backs up
`.mcp.json`, and replaces its server list with one `guardrails` entry. `unwrap`
puts it back byte for byte (step 6).

## 3. Generate a policy

```bash
mcp-guardrails init --pack filesystem
```

`init` finds the filesystem server in the servers file and writes
`~/.mcp-guardrails/policy.yaml`: reads allowed, every change held for approval,
credentials and files that run code later refused. Open it - every rule
carries the comment explaining why it is there. If you also have the GitHub
server configured, `--pack filesystem --pack github` covers both.

## 4. Ask Claude to read the poisoned file

Start `claude` in `examples/demo` and ask:

> Summarize notes/vendor-email.md for me.

The proxy's scanner recognises the planted instructions, so the file comes
back fenced as untrusted data, with a warning naming what fired
(`instruction-override`, `exfiltration`). Claude summarises the email and tells
you about the injection instead of following it. If it does try, the policy
refuses the credential read:

```text
Blocked by guardrails policy rule 'filesystem-no-credentials': This path holds
credentials, and the agent may not read or change it. Ask the user for the
specific value you need instead.
```

## 5. Ask Claude to change a file

> Tick off the first item in TODO.md.

The write matches `filesystem-approve-changes`, so Claude Code shows you an
approval prompt naming the tool, the server and the arguments. Decline it and
the file is untouched; Claude is told it was declined and not to retry.

## 6. Read the audit log

Every call is one JSON line in `~/.mcp-guardrails/audit.jsonl`:

```bash
jq -c 'select(.tool) | {tool, decision, rule, approval, scanner_hits}
       | with_entries(select(.value != null))' ~/.mcp-guardrails/audit.jsonl
```

```json
{"tool":"filesystem__read_text_file","decision":"allow","rule":"filesystem-reads","scanner_hits":["instruction-override","exfiltration"]}
{"tool":"filesystem__write_file","decision":"deny","rule":"filesystem-approve-changes","approval":"declined"}
```

The second line keeps both halves of the story: the rule asked for approval,
and the human said no. The log records names and verdicts, never the file's
contents.

When you are done:

```bash
mcp-guardrails unwrap --client claude-code
```

## Recording it

The README's recording is made from exactly these steps:

```bash
asciinema rec docs/demo.cast   # run steps 2 to 6, then exit
agg docs/demo.cast docs/demo.gif
```

The smoke test reads `vendor-email.md` through a proxy running a policy from
`init`, so the fenced warning in step 4 is checked on every CI run.
