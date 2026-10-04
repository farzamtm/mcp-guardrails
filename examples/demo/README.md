# Demo workspace

A tiny project with one poisoned file, used by [docs/demo.md](../../docs/demo.md)
to show the proxy protecting a real Claude Code session.

- `workspace/README.md` and `workspace/TODO.md` are ordinary files.
- `workspace/notes/vendor-email.md` carries a planted prompt injection: text
  addressed to an AI assistant, telling it to read credentials and send them
  away. Nothing in it is a real secret or a real address.

Do not point an agent at this folder without the proxy in front of it. That is
the point of the demo.
