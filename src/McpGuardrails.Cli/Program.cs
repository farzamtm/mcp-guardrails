using McpGuardrails.Cli.Commands;

// ---------------------------------------------------------------------------
// The entry point.
//
// The proxy is two things at once:
//   - an MCP SERVER, which the client (Claude Desktop) talks to over stdio -
//     or, with --transport http, over Streamable HTTP
//   - an MCP CLIENT, which talks to the real downstream servers
//
// Each subcommand is a small class under Commands/, picked by CommandTable.
// What happens to a tool call lives in GuardrailsCallPipeline in Core, where it
// is unit-tested; the CLI is covered end to end by scripts/smoke.py instead.
//
// This file is a "top-level program": C# allows bare statements as the entry
// point, and generates the `class Program { static Main }` wrapper for you.
// ---------------------------------------------------------------------------
return await CommandTable.RunAsync(args);
