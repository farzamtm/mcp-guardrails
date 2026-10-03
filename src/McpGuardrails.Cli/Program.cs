using McpGuardrails.Cli;
using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Audit;
using McpGuardrails.Core.Budget;
using McpGuardrails.Core.Hosting;
using McpGuardrails.Core.Pipeline;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Scanners;
using McpGuardrails.Core.Upstream;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.AspNetCore;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

// ---------------------------------------------------------------------------
// The composition root.
//
// The proxy is two things at once:
//   - an MCP SERVER, which the client (Claude Desktop) talks to over stdio -
//     or, with --transport http, over Streamable HTTP
//   - an MCP CLIENT, which talks to the real downstream servers
//
// This file only wires them together. What happens to a tool call lives in
// GuardrailsCallPipeline in Core, where it is unit-tested; this file is covered
// end to end by scripts/smoke.py instead.
//
// This file is a "top-level program": C# allows bare statements as the entry
// point, and generates the `class Program { static Main }` wrapper for you.
// ---------------------------------------------------------------------------

// A plain argument scan rather than a command-line parser: four flags and one
// subcommand do not justify a dependency.
var listOnly = args.Contains("list-upstream", StringComparer.Ordinal);

// --explain appends the policy decision trail to every denial, so "why was this
// blocked?" is answerable without reading the rules. Off by default: building
// the trail allocates on a path that runs for every single tool call.
var explain = args.Contains("--explain", StringComparer.Ordinal);

// Which transport the server half listens on. Parsed before anything is spawned,
// so a bad or unsafe command line fails in milliseconds rather than after every
// downstream server has started - and fails rather than guessing.
ServeOptions serve;
try
{
    serve = ServeOptions.Parse(args, Environment.GetEnvironmentVariable(ServeOptions.TokenVariable));
}
catch (ServeOptionsException ex)
{
    await Console.Error.WriteLineAsync(ex.Message);
    return 2;
}

// --injection-classifier turns on the LLM second stage of the injection scanner
// with its defaults (confirm mode, Haiku, ANTHROPIC_API_KEY) when the policy does
// not configure it. A policy `classifier:` block always wins, including one that
// says `mode: off`: the file is the reviewed, committed statement of intent, and
// a flag in a launcher config should not be able to quietly override it.
var classifierFlag = args.Contains("--injection-classifier", StringComparer.Ordinal);

// OpenTelemetry export is opt-in. Setting the standard OTLP endpoint variable is
// itself the opt-in, so the proxy behaves like any other OTel-instrumented
// process; --otel means "export to the default collector on localhost". Off by
// default because a security tool should not open network connections nobody
// asked for.
var otel = args.Contains("--otel", StringComparer.Ordinal)
           || !string.IsNullOrWhiteSpace(
               Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT"));

// Reported as the MCP server version and as the OTel service.version, so a
// trace and a client's server list agree on what was running.
var proxyVersion = ProxyVersion.Of(typeof(Program).Assembly);

// Where the sandboxed filesystem server is allowed to operate.
var sandbox = Environment.GetEnvironmentVariable("GUARDRAILS_SANDBOX")
              ?? Path.Combine(Path.GetTempPath(), "guardrails-sandbox");
Directory.CreateDirectory(sandbox);

// Where the audit log lands.
var auditPath = ConfigPath("GUARDRAILS_AUDIT", "audit.jsonl");

// Both builders implement IHostApplicationBuilder, so everything below - logging,
// and above all the MCP server with its guardrail filters - is configured once,
// through the interface, for whichever transport was chosen. Only the listener
// differs. The slim builder because it is the AOT-friendly one.
WebApplicationBuilder? web = null;
IHostApplicationBuilder builder;

if (serve.Transport is Transport.Http)
{
    web = WebApplication.CreateSlimBuilder(args);
    HttpHost.ConfigureListener(web, serve);
    builder = web;
}
else
{
    builder = Host.CreateApplicationBuilder(args);
}

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
LogToStandardError(builder.Logging);

// Created unconditionally: with no exporter attached the span and instruments
// are inert, and the audit filter does not need a second code path.
using var telemetry = new ToolCallTelemetry();

if (otel)
{
    // Traces and metrics only, not logs. The proxy's log lines are for the
    // operator's terminal; exporting them would be a second, unreviewed channel
    // out of the process.
    //
    // "Experimental.ModelContextProtocol" is the MCP SDK's own source and meter.
    // Subscribing to it adds the semconv tools/call server span above ours and a
    // client span per downstream call beneath it, so one trace shows the whole
    // hop: client -> guardrails -> downstream server.
    //
    // Endpoint, protocol, headers, export intervals and OTEL_SDK_DISABLED come
    // from the standard OTEL_* environment variables, read by the SDK. The
    // exporter writes to the network, never to stdout, so the JSON-RPC wire is
    // not at risk.
    const string McpSdkSource = "Experimental.ModelContextProtocol";

    builder.Services.AddOpenTelemetry()
        .ConfigureResource(resource =>
            resource.AddService("mcp-guardrails", serviceVersion: proxyVersion))
        .WithTracing(tracing => tracing
            .AddSource(ToolCallTelemetry.SourceName, McpSdkSource)
            .AddOtlpExporter())
        .WithMetrics(metrics => metrics
            .AddMeter(ToolCallTelemetry.SourceName, McpSdkSource)
            .AddOtlpExporter());
}

// A second factory for what runs before the host exists - connecting upstream,
// the audit sink, startup warnings - configured identically, so a log line looks
// the same whichever of the two wrote it.
using var loggerFactory = LoggerFactory.Create(LogToStandardError);

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
await using var audit = new JsonlAuditSink(
    auditPath, logger: loggerFactory.CreateLogger<JsonlAuditSink>());

// ---------------------------------------------------------------------------
// Load the policy.
//
// A missing file is not an error: no policy means pure passthrough with audit
// logging, which is the adoption story. A MALFORMED file is fatal - failing
// open on a broken security policy is exactly the wrong default.
// ---------------------------------------------------------------------------
var policyPath = ConfigPath("GUARDRAILS_POLICY", "policy.yaml");

// One client for the life of the process, as HttpClient is designed to be used.
// Infinite timeout because the injection gate owns the classifier deadline;
// two competing timeouts would make "timed out" mean two different things.
// Created unconditionally because it is cheap and opens no connection until used.
using var classifierHttp = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };

PolicyEvaluator policy;
PolicyDocument document;
BudgetPolicy budgets;
InjectionGate scanner;
SecretGate secrets;
ScannerSettings injection;
try
{
    document = PolicyLoader.LoadFromFileOrEmpty(policyPath);

    policy = new PolicyEvaluator(document);
    budgets = document.EffectiveBudgets;

    // On by default, including with no policy file at all: a result scanner that
    // has to be switched on protects nobody, and annotating cannot break a call.
    injection = document.EffectiveScanners.EffectiveInjection;

    if (classifierFlag && injection.Classifier is null)
    {
        injection = injection with { Classifier = ClassifierSettings.Default };
    }

    // Also on by default. Out of the box it changes no call - arguments are
    // forwarded as sent and only the audit log is scrubbed - but it does redact
    // secrets from results, because a key the model has read cannot be unread.
    var secretSettings = document.EffectiveScanners.EffectiveSecrets;
    secrets = new SecretGate(secretSettings);

    // The classifier is opt-in and off by default: it sends tool output to a
    // third party and costs money per call. A missing API key is a startup
    // error (PolicyException, caught below) rather than a classifier that
    // silently fails on every call. It runs inside the secret gate, so it
    // redacts for itself before anything leaves the process.
    scanner = injection.UsesClassifier
        ? new InjectionGate(
            injection,
            new RedactingInjectionClassifier(
                AnthropicInjectionClassifier.Create(
                    injection.Classifier!,
                    classifierHttp,
                    Environment.GetEnvironmentVariable),
                secretSettings.IncludePii))
        : new InjectionGate(injection);
}
catch (PolicyException ex)
{
    // Console.Error, not stdout: stdout is the JSON-RPC wire.
    await Console.Error.WriteLineAsync($"Invalid policy file '{policyPath}': {ex.Message}");
    return 1;
}

// A valid policy can still ask for something the chosen transport cannot do:
// a session budget over stateless HTTP would quietly become one pool shared by
// every client. Exit code 2 like the other transport refusals, because the
// policy is fine - it is the combination with --transport that is not.
try
{
    serve.EnsureEnforceable(budgets);
}
catch (ServeOptionsException ex)
{
    await Console.Error.WriteLineAsync($"Policy file '{policyPath}': {ex.Message}");
    return 2;
}

// ---------------------------------------------------------------------------
// Scan the tool definitions, once.
//
// Descriptions and schemas from tools/list are read by the model as if they
// were instructions, before any call has happened - "tool poisoning" - and the
// result scanner never sees them. The registry fetched them once at connect
// time, so they are scanned once here and the outcome is what tools/list serves
// and what the policy filter consults for every call. Heuristics only; see
// ToolMetadataGate for why the classifier is not asked.
// ---------------------------------------------------------------------------
var toolMetadata = ToolMetadataGate.Build(
    injection,
    upstream.Connections.SelectMany(connection =>
        connection.Tools.Select(tool => (connection.Name, tool.ProtocolTool))));

// Logged in list-upstream mode too (its level is Warning), because that is the
// command an operator runs to see what a server advertises - and the place a
// false positive should be found, before it hides a tool in production.
var metadataLog = loggerFactory.CreateLogger<ToolMetadataGate>();
foreach (var finding in toolMetadata.Findings)
{
    metadataLog.LogWarning(
        "Tool '{Tool}' from server '{Server}': its {Fields} matched prompt-injection heuristics ({Heuristics}); {Action}.",
        finding.Tool,
        finding.Server,
        string.Join(", ", finding.Fields),
        finding.Report.Summary,
        finding.Effect is ScanEffect.Blocked
            ? "withheld from tools/list and calls to it are refused"
            : "its description is prefixed with a warning");
}

// list-upstream only prints what the servers advertise, then exits - before the
// budget store is opened, so it creates no database file (the example-policy
// check in CI runs exactly this), and before the metadata findings are audited,
// so listing tools never adds lines to the operator's log.
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

// Where daily budget counters persist. An environment variable like the audit
// and policy paths, not a policy key: the policy says what the limits are, the
// deployment says where state lives - and two agents sharing one policy file
// may well want separate daily budgets. Every proxy pointed at the same file
// shares one budget. Only opened when `budgets.daily` is configured.
var budgetDbPath = ConfigPath("GUARDRAILS_BUDGET_DB", "budgets.db");

// Captured so it can be disposed on exit; null when no daily cap is configured.
SqliteBudgetStore? dailyStore = null;
BudgetGate budget;

try
{
    // No `budgets:` section means an unlimited gate rather than no gate: the
    // call path is then the same whether or not anyone configured a cap, so
    // the configured path is not the one that only ever runs in production.
    budget = BudgetGate.For(budgets, limits => dailyStore = new SqliteBudgetStore(budgetDbPath, limits));
}
catch (Exception ex) when (ex is SqliteException or IOException or UnauthorizedAccessException)
{
    // Fatal, like a malformed policy: running without the daily cap the
    // operator asked for would be failing open.
    await Console.Error.WriteLineAsync($"Cannot open budget store '{budgetDbPath}': {ex.Message}");
    return 1;
}

using var dailyStoreLifetime = dailyStore;

// One audit line per flagged tool.
foreach (var finding in toolMetadata.Findings)
{
    await audit.WriteAsync(finding.ToAuditRecord(DateTimeOffset.UtcNow), CancellationToken.None);
}

// ---------------------------------------------------------------------------
// The webhook approver, if the policy configures one.
//
// Built here, after list-upstream has returned, because this is the first point
// that needs the signing secret: listing (and CI's example-policy check) should
// work on a machine that does not hold it. Serving without it is fatal, for the
// same reason a malformed policy is - a rule routed to an approver we cannot
// authenticate to would deny every call, and the operator should hear about it
// now rather than from the first refusal.
// ---------------------------------------------------------------------------
WebhookApprovalChannel? webhook = null;
if (document.EffectiveApprovers.Webhook is { } webhookSettings)
{
    try
    {
        webhook = new WebhookApprovalChannel(
            webhookSettings.Endpoint,
            webhookSettings.ReadSecret(Environment.GetEnvironmentVariable),
            WebhookApprovalChannel.CreateHandler(),
            document.EffectiveScanners.EffectiveSecrets);
    }
    catch (PolicyException ex)
    {
        await Console.Error.WriteLineAsync($"Invalid policy file '{policyPath}': {ex.Message}");
        return 1;
    }
}

using var webhookLifetime = webhook;

// Who an in-band require_approval call is put to. Over stdio, the human at the
// client via elicitation. Over stateless HTTP there is no channel back to the
// client, so the answer is "nobody", given immediately - see
// StatelessHttpApprovalChannel. A `mode: webhook` rule does not depend on the
// client, so it works the same on either transport.
Func<McpServer, IApprovalChannel> approvalChannel = serve.Transport is Transport.Http
    ? _ => StatelessHttpApprovalChannel.Instance
    : server => new ElicitationApprovalChannel(server, document.EffectiveScanners.EffectiveSecrets);

var pipeline = new GuardrailsCallPipeline(
    upstream,
    audit,
    telemetry,
    policy,
    toolMetadata,
    secrets,
    budget,
    scanner,
    webhook,
    explain);

// ---------------------------------------------------------------------------
// Serve the aggregated tools.
//
// Instead of registering tools of our own, we supply two handlers - the merged
// tool list and the forward - and one call filter wrapped around the forward
// that runs every guardrail. The filter is the only place SDK request types
// meet the pipeline, which takes plain protocol DTOs so it can be tested
// without a live session.
// ---------------------------------------------------------------------------
var mcp = builder.Services
    .AddMcpServer(options =>
    {
        options.ServerInfo = new Implementation { Name = "mcp-guardrails", Version = proxyVersion };

        options.Filters.Request.CallToolFilters.Add(next => (request, cancellationToken) =>
            pipeline.InvokeAsync(
                request.Params,
                approvalChannel(request.Server),
                forwardToken => next(request, forwardToken),
                cancellationToken));
    })
    .WithListToolsHandler((_, _) =>
    {
        // Built once at startup, already qualified with the same namer the call
        // handler resolves through - so the client never sees a tool it cannot
        // invoke - and already scanned. A fresh list per request because the
        // result DTO is mutable and must not be shared between clients.
        var tools = toolMetadata.Tools.ToList();

        // The handler is synchronous, but the delegate returns ValueTask, so wrap
        // the finished value rather than paying for a state machine.
        return ValueTask.FromResult(new ListToolsResult { Tools = tools });
    })
    .WithCallToolHandler((request, cancellationToken) =>
        pipeline.ForwardAsync(request.Params, cancellationToken));

if (web is not null)
{
    // Stateless is the SDK default as of the 2026-07-28 revision; spelled out
    // because the approval behaviour above depends on it.
    mcp.WithHttpTransport(options => options.SessionMode = HttpServerSessionMode.Stateless);

    await HttpHost.RunAsync(web.Build(), serve);
}
else
{
    mcp.WithStdioServerTransport();

    await ((HostApplicationBuilder)builder).Build().RunAsync();
}

return 0;

// Every log line goes to stderr - see the stdout warning above. list-upstream
// prints its listing to stdout and wants only warnings beside it.
void LogToStandardError(ILoggingBuilder logging)
{
    logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);
    logging.SetMinimumLevel(listOnly ? LogLevel.Warning : LogLevel.Information);
}

// The deployment's choice of file, else a stable default under the home
// directory. Stable matters: launched from Claude Desktop the process has no cwd
// you can predict, so a relative default would scatter files wherever the client
// happened to start us.
static string ConfigPath(string variable, string fileName) =>
    Environment.GetEnvironmentVariable(variable)
    ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".mcp-guardrails",
        fileName);
