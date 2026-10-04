# Research: what public MCP servers tell your agent

> **Status: methodology only.** No study has been run and nothing below is a
> result. Every `TBD` is a placeholder. Results are published here only after the
> disclosure process in [Ethics](#ethics) is complete.

This page is the plan and the write-up template for a survey of the tool
definitions that public MCP servers advertise, measured with
[`mcp-guardrails scan`](../scan.md). It exists before the data so that the method
is fixed, and visible, before anyone looks at the numbers.

## Question

What do public MCP servers put in front of the model before it has done anything,
and how much of it would a guardrail flag?

- How often do descriptions or schemas carry text shaped like instructions to the
  model?
- How honest are behaviour annotations: how many tools declare none, and how many
  "read-only" tools are named or described like writes?
- How often do schemas suggest values the argument detectors would flag?
- How often do published install instructions run an unpinned package?
- How much do definitions change between releases?
- How common are invisible or bidirectional Unicode characters?

## Population

To be fixed before any data is collected, and recorded here with the date and
the exact query used.

| Source | How it is enumerated | Size |
| --- | --- | --- |
| The official MCP registry | The registry's public API (verify the endpoint and its terms at collection time) | TBD |
| npm and PyPI packages tagged `mcp` | The top N by downloads, N fixed in advance | TBD |
| Docker's MCP catalog | The published catalog | TBD |

Duplicates across sources are merged by package name and version. Servers that
need credentials to start, or are remote-only behind OAuth, are counted and
reported as "not scannable" rather than dropped silently.

## Method

1. **Isolation.** Each server is started in a disposable container with no
   network access and no credentials, from the exact version listed. Nothing is
   ever called: only `initialize` and `tools/list`.
2. **Capture.** `mcp-guardrails scan --json` against a one-server servers file
   per package. The raw `tools/list` response is kept alongside, for
   re-analysis with later scanner versions.
3. **Drift.** The same population is captured again at fixed intervals over
   several weeks. The per-tool `hash` field (the same canonical hash
   [pinning](../pins.md) uses) shows which definitions changed between releases
   without diffing text by hand.
4. **Versions.** The proxy version, scanner settings and container image digest
   are recorded with every capture, so every number can be reproduced.

## Measurements

| Measurement | Source in the scan report | Result |
| --- | --- | --- |
| Servers scanned / not scannable | `servers`, `unavailable` | TBD |
| Tools with injection-shaped text, by heuristic | `findings[check=injection].names` | TBD |
| Tools declaring no annotations | `annotations` empty | TBD |
| "Read-only" tools named or described like writes | `findings[check=read-only-mismatch]` | TBD |
| Tools whose schema suggests a flagged value, by detector | `findings[check=schema-suggestion].names` | TBD |
| Tools with hidden or bidirectional Unicode | `findings[check=injection].names` contains `hidden-text` | TBD |
| Install instructions running an unpinned package | The servers-file warning for package runners | TBD |
| Definitions changed per release | `hash` across captures | TBD |

Each heuristic match is reviewed by hand before it is counted as a finding, and
the false-positive rate of each check is reported next to its numbers.

## Ethics

- No exploitation, no credentials, no network for the servers under test, and no
  tool is ever called.
- **Responsible disclosure first.** Anything server-specific is reported
  privately to the maintainer before publication, with 90 days or a coordinated
  date, whichever comes first. A server is named in the results only after its
  maintainer has been told.
- What is published: aggregate results, the anonymized dataset, and the scanning
  harness, all open source.
- What is not published: working payloads, or anything that turns a finding into
  instructions for attacking a specific deployment.

## Results

TBD. Published here after disclosure.

## Reproducing

TBD: the harness, the population list with versions, and the commands, once the
first capture is done.
