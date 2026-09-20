using System.Diagnostics;
using McpGuardrails.Cli;
using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Audit;
using McpGuardrails.Core.Budget;
using McpGuardrails.Core.Pipeline;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Scanners;
using McpGuardrails.Core.Upstream;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;

// ---------------------------------------------------------------------------
// STEP 3 - the pass-through proxy.
//
// The proxy is two things at once:
//   - an MCP SERVER, which the client (Claude Desktop) talks to over stdio
//   - an MCP CLIENT, which talks to the real downstream servers
//
// This file is a "top-level program": C# allows bare statements as the entry
// point, and generates the `class Program { static Main }` wrapper for you.
// ---------------------------------------------------------------------------

// A crude command switch. Step 11 replaces this with System.CommandLine; right
// now an extra dependency would only obscure the MCP concepts.
var listOnly = args.Contains("list-upstream", StringComparer.Ordinal);

// --explain appends the policy decision trail to every denial, so "why was this
// blocked?" is answerable without reading the rules. Off by default: building
// the trail allocates on a path that runs for every single tool call.
var explain = args.Contains("--explain", StringComparer.Ordinal);

// Where the sandboxed filesystem server is allowed to operate.
var sandbox = Environment.GetEnvironmentVariable("GUARDRAILS_SANDBOX")
              ?? Path.Combine(Path.GetTempPath(), "guardrails-sandbox");
Directory.CreateDirectory(sandbox);

// Where the audit log lands. A stable, discoverable default matters: launched
// from Claude Desktop the process has no cwd you can predict, so a relative
// path would scatter logs wherever the client happened to start us.
var auditPath = Environment.GetEnvironmentVariable("GUARDRAILS_AUDIT")
                ?? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".mcp-guardrails",
                    "audit.jsonl");

var builder = Host.CreateApplicationBuilder(args);

// ---------------------------------------------------------------------------
// CRITICAL for stdio servers: stdout is the JSON-RPC wire.
//
// The default host logs to stdout. Any log line landing there is interleaved
// with protocol frames and the client's JSON parser dies on it. So: clear the
// default providers and force every log to stderr.
//
// This is the single most common way to break an stdio MCP server.
// ---------------------------------------------------------------------------
builder.Logging.ClearProviders();
builder.Logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);
builder.Logging.SetMinimumLevel(listOnly ? LogLevel.Warning : LogLevel.Information);

using var loggerFactory = LoggerFactory.Create(logging =>
{
    logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);
    logging.SetMinimumLevel(listOnly ? LogLevel.Warning : LogLevel.Information);
});

// ---------------------------------------------------------------------------
// Connect to every downstream server and cache the tools they advertise.
//
// `await using` is `using` for IAsyncDisposable: when this scope ends, the
// registry's DisposeAsync runs and every spawned child process is shut down.
// ---------------------------------------------------------------------------
await using var upstream = await UpstreamRegistry.ConnectAsync(
    DefaultUpstreams.Create(sandbox),
    loggerFactory);

// Declared after the registry so it is disposed BEFORE it: `await using` unwinds
// in reverse order, so the sink drains its queue while the tool calls that feed
// it are already finished.
await using var audit = new JsonlAuditSink(auditPath);

// ---------------------------------------------------------------------------
// Load the policy.
//
// A missing file is not an error: no policy means pure passthrough with audit
// logging, which is the adoption story. A MALFORMED file is fatal - failing
// open on a broken security policy is exactly the wrong default.
// ---------------------------------------------------------------------------
var policyPath = Environment.GetEnvironmentVariable("GUARDRAILS_POLICY")
                 ?? Path.Combine(
                     Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                     ".mcp-guardrails",
                     "policy.yaml");

PolicyEvaluator policy;
BudgetGate budget;
InjectionGate scanner;
try
{
    var document = PolicyLoader.LoadFromFileOrEmpty(policyPath);

    policy = new PolicyEvaluator(document);

    // On by default, including with no policy file at all: a result scanner that
    // has to be switched on protects nobody, and annotating cannot break a call.
    scanner = new InjectionGate(document.EffectiveScanners.EffectiveInjection);

    // No `budgets:` section means an unlimited gate rather than no gate: the
    // call path is then the same whether or not anyone configured a cap, so the
    // configured path is not the one that only ever runs in production.
    budget = document.EffectiveBudgets.Session is { } session
        ? new BudgetGate(new InMemoryBudgetStore(session))
        : BudgetGate.Unlimited;
}
catch (PolicyException ex)
{
    // Console.Error, not stdout: stdout is the JSON-RPC wire.
    await Console.Error.WriteLineAsync($"Invalid policy file '{policyPath}': {ex.Message}");
    return 1;
}

// ---------------------------------------------------------------------------
// STEP 2 demo: print what we discovered downstream, then exit.
// ---------------------------------------------------------------------------
if (listOnly)
{
    foreach (var connection in upstream.Connections)
    {
        Console.WriteLine($"{connection.Name}  ({connection.Tools.Count} tools)");
        foreach (var tool in connection.Tools)
        {
            Console.WriteLine($"  {ToolNamespacer.Qualify(connection.Name, tool.Name),-40} {tool.Description?.ReplaceLineEndings(" ")}");
        }
    }

    return 0;
}

// The name a call is known by when the client did not send one. Shared by the
// audit filter and the policy filter on purpose: if they disagreed, the log and
// the policy would describe different calls, in exactly the malformed-traffic
// case where someone reading the log afterwards most needs to trust it.
const string UnnamedTool = "(missing)";

// ---------------------------------------------------------------------------
// STEP 3: serve the aggregated tools.
//
// Instead of registering tools of our own, we supply two handlers:
//
//   WithListToolsHandler - merges every downstream tool list into one, with
//                          names rewritten into the proxy's namespace
//   WithCallToolHandler  - routes an incoming call to the owning server
//
// Right now both are pure pass-through. Every guardrail in the spec - policy,
// budget, approval, redaction - becomes a filter wrapped around these.
// ---------------------------------------------------------------------------
builder.Services
    .AddMcpServer(options =>
    {
        options.ServerInfo = new Implementation { Name = "mcp-guardrails", Version = "0.1.0" };

        // -------------------------------------------------------------------
        // THE INTERCEPTOR PIPELINE.
        //
        // A filter takes the next handler and returns a replacement wrapping it.
        // That is the whole middleware pattern - ASP.NET, Express and servlet
        // filters are all this shape:
        //
        //     next => async (request, ct) => { before; await next(...); after; }
        //
        // Filters nest like onion layers, so the FIRST one added is the
        // outermost. Audit goes on first deliberately: it must observe calls
        // that inner layers (policy, budget, approval) reject, otherwise the
        // log would only show what was permitted.
        // -------------------------------------------------------------------
        options.Filters.Request.CallToolFilters.Add(next => async (request, cancellationToken) =>
        {
            // Opens the per-call scope that lets the policy filter below report
            // its decision back up to this one. See GuardrailsCallScope for why
            // a mutable holder is required rather than a plain AsyncLocal value.
            using var scope = GuardrailsCallScope.Begin();

            var toolName = request.Params?.Name ?? UnnamedTool;

            // Resolve purely to enrich the log. The call handler resolves again
            // to actually route; duplicating a dictionary lookup is cheaper than
            // coupling the two concerns together.
            var resolved = upstream.TryResolve(toolName, out var connection, out var downstreamName);

            // Stopwatch timestamps rather than DateTime subtraction: this reads a
            // monotonic clock, so an NTP correction mid-call cannot produce a
            // negative duration.
            var startedAt = Stopwatch.GetTimestamp();

            CallToolResult? result = null;
            string? failure = null;

            try
            {
                result = await next(request, cancellationToken);
                return result;
            }
            catch (Exception ex)
            {
                // Record the failure, then rethrow. The audit sink observes; it
                // must never change the outcome of a call.
                failure = $"{ex.GetType().Name}: {ex.Message}";
                throw;
            }
            finally
            {
                var decision = scope.Decision;

                var record = new AuditRecord
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    Event = "tool_call",
                    Tool = toolName,
                    Server = resolved ? connection.Name : null,
                    DownstreamTool = resolved ? downstreamName : null,
                    Arguments = request.Params?.Arguments?.AsReadOnly(),
                    Decision = decision?.Verdict.ToString().ToLowerInvariant(),
                    Rule = decision?.RuleName,
                    DecisionReason = decision?.Reason,
                    Approval = Describe(decision?.ApprovalResult),
                    // Null unless something matched, so a clean result stays one
                    // narrow line and `jq 'select(.scanner_hits)'` is the whole
                    // query for "show me what the scanner caught".
                    ScannerHits = scope.Scan is { Effect: not ScanEffect.None } scan
                        ? scan.Heuristics
                        : null,
                    ScannerAction = scope.Scan?.Describe(),
                    DurationMs = Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds,
                    IsError = failure is not null || result?.IsError is true,
                    Error = failure,
                };

                // CancellationToken.None on purpose: if the caller cancelled, we
                // still want the record. Losing the evidence of an aborted call
                // is exactly the case an audit log exists for.
                await audit.WriteAsync(record, CancellationToken.None);
            }
        });

        // -------------------------------------------------------------------
        // POLICY AND BUDGET FILTER - registered second, so it sits INSIDE audit.
        //
        // That ordering is the point: when this filter refuses a call it returns
        // without invoking `next`, so nothing downstream runs - but the audit
        // filter wrapping it still records the attempt.
        // -------------------------------------------------------------------
        options.Filters.Request.CallToolFilters.Add(next => async (request, cancellationToken) =>
        {
            var toolName = request.Params?.Name ?? UnnamedTool;

            // The tool definition carries the annotations rules match on. An
            // unknown name yields null, and policy still runs: a catch-all deny
            // has to cover calls the proxy was going to reject anyway, or the
            // audit log and the policy would tell different stories.
            upstream.TryGetTool(toolName, out var tool);

            var facts = PolicyFacts.ForCall(toolName, request.Params, tool);

            // Three gates, in this order, and the order is the design.
            //
            // The policy decides whether the call is permitted at all. Approval
            // turns a 'require_approval' verdict into a real answer from a real
            // human - which can only happen before the budget runs, because a
            // call waiting on a person has not been forwarded and must not be
            // charged. Budget then decides whether there is anything left to
            // spend on the call that is finally going out.
            var decision = policy.Evaluate(facts, explain);

            decision = await ApprovalGate.ApplyAsync(
                decision,
                facts,
                new ElicitationApprovalChannel(request.Server),
                cancellationToken);

            decision = budget.Apply(decision);

            // Report upward so the audit record carries the verdict.
            GuardrailsCallScope.RecordDecision(decision);

            if (!decision.IsBlocked)
            {
                return await next(request, cancellationToken);
            }

            // A refusal is returned as a tool ERROR, not a JSON-RPC protocol
            // error. Protocol errors are for malformed traffic; this is a result
            // the model should read and adapt to. That is why the message is
            // written for the model rather than for a log file.
            var text = decision.ToModelMessage();

            if (explain && decision.Trail is { Count: > 0 })
            {
                text += "\n\nDecision trail:\n  " + string.Join("\n  ", decision.Trail);
            }

            return new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text = text }],
            };
        });

        // -------------------------------------------------------------------
        // RESULT SCANNER - registered last, so it is the INNERMOST layer.
        //
        // Everything above this point guards the way in. This one is the first
        // guardrail that runs on the way back, and innermost is the only correct
        // position for it: it must see what a downstream server actually
        // returned, and must not see the refusals the gates above it produce -
        // those are the proxy's own words, addressed to the model.
        // -------------------------------------------------------------------
        options.Filters.Request.CallToolFilters.Add(next => async (request, cancellationToken) =>
        {
            var result = await next(request, cancellationToken);

            var outcome = scanner.Inspect(result, request.Params?.Name ?? UnnamedTool);

            // Report upward so the audit record carries the finding, exactly as
            // the policy filter reports its decision.
            GuardrailsCallScope.RecordScan(outcome);

            return outcome.Result;
        });
    })
    .WithStdioServerTransport()
    .WithListToolsHandler((_, _) =>
    {
        var tools = upstream.Connections
            .SelectMany(connection => connection.Tools.Select(tool =>
                // The name advertised here MUST match what the call handler below
                // resolves, or the client sees a tool it cannot invoke.
                ToolNamespacer.Qualify(connection.Name, tool.ProtocolTool)))
            .ToList();

        // The handler is synchronous, but the delegate returns ValueTask, so wrap
        // the finished value rather than paying for a state machine.
        return ValueTask.FromResult(new ListToolsResult { Tools = tools });
    })
    .WithCallToolHandler(async (request, cancellationToken) =>
    {
        var requestedName = request.Params?.Name;

        if (requestedName is null ||
            !upstream.TryResolve(requestedName, out var connection, out var downstreamName))
        {
            // Return a tool ERROR, not a JSON-RPC protocol error. This is a
            // deliberate distinction: protocol errors are for malformed traffic,
            // whereas "that tool does not exist" is a result the model should
            // read and react to. The same reasoning drives the model-readable
            // denial messages the policy engine will produce in step 5.
            return new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text = $"Unknown tool '{requestedName}'." }],
            };
        }

        // -------------------------------------------------------------------
        // THE FORWARD. Everything before this line is "on the way in", and
        // everything after it is "on the way back" - the two halves of the
        // interceptor pipeline in the spec.
        // -------------------------------------------------------------------
        return await connection.Client.CallToolAsync(
            new CallToolRequestParams
            {
                Name = downstreamName,
                Arguments = request.Params?.Arguments,
            },
            cancellationToken);
    });

await builder.Build().RunAsync();

return 0;

// A local function, so the audit filter above can render the approval outcome
// without either duplicating the mapping or exposing a wire format from Core.
// snake_case to match every other value in the log, so `jq 'select(.approval ==
// "timed_out")'` reads the way an operator expects.
static string? Describe(ApprovalOutcome? outcome) => outcome switch
{
    ApprovalOutcome.Approved => "approved",
    ApprovalOutcome.Declined => "declined",
    ApprovalOutcome.TimedOut => "timed_out",
    ApprovalOutcome.Unavailable => "unavailable",
    ApprovalOutcome.Failed => "failed",
    _ => null,
};
