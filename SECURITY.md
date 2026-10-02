# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue.

Report privately via [GitHub Security Advisories][advisories] or by email to
<farzamit@gmail.com>.

Useful things to include: what an attacker can achieve, the steps to reproduce
it, and the version or commit you tested.

This is a personal project maintained in spare time. Expect an acknowledgement
within a week. There is no bug bounty.

[advisories]: https://github.com/farzamtm/mcp-guardrails/security/advisories/new

## Scope

In scope — anything that lets a caller get past the proxy's controls:

- Bypassing a policy decision (a call that should be denied is forwarded)
- Bypassing an approval gate
- Injection content in tool results that evades the scanner
- Secrets appearing unredacted in the audit log
- Path or namespace confusion in tool routing (a call reaching the wrong server)
- Crashing the proxy in a way that fails **open** rather than closed
- Reaching the Streamable HTTP endpoint without the configured bearer token, or
  from a browser page on another origin

Out of scope:

- Vulnerabilities in downstream MCP servers the proxy fronts
- Vulnerabilities in the MCP client
- Anything requiring an attacker who already has write access to your policy
  file or local machine

## Threat model

The proxy sits between an MCP client and the servers it calls. It assumes:

- The **client** is trusted but its *model* is not reliably steerable. The whole
  premise is that an LLM can be talked into calling a tool it should not.
- **Tool results are untrusted input.** Anything a downstream server returns may
  have been authored by an attacker and will be read by the model as though it
  were instructions. This is the primary attack the project targets.
- **Downstream servers are semi-trusted.** The proxy does not sandbox them; it
  observes and gates the calls made to them.
- The **policy file and the audit log** are trusted. An attacker who can rewrite
  either has already won, and defending against that is the operating system's
  job, not this tool's.

### What this tool does not protect against

Stating the limits plainly, because a security tool that overstates its coverage
is worse than none:

- It does not stop a *legitimately permitted* tool call from doing damage. If
  policy allows `write_file`, the agent may still write the wrong thing.
- It does not sandbox downstream servers. A malicious MCP server can do whatever
  its own process permissions allow.
- Injection scanning is **heuristic**. It raises the cost of an attack; it does
  not eliminate it. Do not treat a clean scan as proof of safety.
- It does not protect against a compromised MCP client or a compromised host.
- It does not encrypt or access-control the audit log. That is a filesystem
  permissions question.
- The Streamable HTTP host serves plain HTTP, with one optional shared bearer
  token and no per-client identity. It binds loopback by default; anything
  wider belongs behind a TLS-terminating reverse proxy you trust. With no
  per-client identity there is no per-client budget either: session budgets
  are refused over HTTP, and the daily budget is shared by every client.

## Supported versions

Pre-1.0. Only the latest commit on `main` is supported.
