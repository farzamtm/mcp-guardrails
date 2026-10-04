using McpGuardrails.Core.Audit;
using McpGuardrails.Core.Budget;
using McpGuardrails.Core.Hosting;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Scanners;
using McpGuardrails.Core.Upstream;
using Microsoft.Extensions.Logging;

namespace McpGuardrails.Cli.Commands;

/// <summary>
/// What serving and listing have in common: the command line checked, every
/// downstream server connected, the policy loaded and the tool definitions
/// scanned.
/// </summary>
/// <remarks>
/// list-upstream runs exactly this and stops, so what it prints is what the
/// proxy would serve - including the effect of the metadata scanner and a policy
/// that fails to load.
/// </remarks>
internal sealed class ProxyStartup : IAsyncDisposable
{
    private ProxyStartup(
        ServeOptions serve,
        ILoggerFactory loggerFactory,
        UpstreamRegistry upstream,
        JsonlAuditSink audit,
        HttpClient classifierHttp,
        string policyPath,
        PolicyDocument document,
        PolicyEvaluator policy,
        BudgetPolicy budgets,
        InjectionGate scanner,
        SecretGate secrets,
        ToolMetadataGate toolMetadata)
    {
        Serve = serve;
        LoggerFactory = loggerFactory;
        Upstream = upstream;
        Audit = audit;
        ClassifierHttp = classifierHttp;
        PolicyPath = policyPath;
        Document = document;
        Policy = policy;
        Budgets = budgets;
        Scanner = scanner;
        Secrets = secrets;
        ToolMetadata = toolMetadata;
    }

    public ServeOptions Serve { get; }

    /// <summary>For what runs before the host exists, or without one.</summary>
    public ILoggerFactory LoggerFactory { get; }

    public UpstreamRegistry Upstream { get; }

    public JsonlAuditSink Audit { get; }

    private HttpClient ClassifierHttp { get; }

    public string PolicyPath { get; }

    public PolicyDocument Document { get; }

    public PolicyEvaluator Policy { get; }

    public BudgetPolicy Budgets { get; }

    public InjectionGate Scanner { get; }

    public SecretGate Secrets { get; }

    public ToolMetadataGate ToolMetadata { get; }

    /// <summary>Runs the shared startup.</summary>
    /// <param name="args">The full command line.</param>
    /// <param name="listing">
    /// True for list-upstream, which prints its listing to stdout and wants only
    /// warnings beside it.
    /// </param>
    /// <exception cref="CommandFailedException">Anything that makes the proxy refuse to start.</exception>
    public static async Task<ProxyStartup> LoadAsync(string[] args, bool listing)
    {
        // Which transport the server half listens on. Parsed before anything is
        // spawned, so a bad or unsafe command line fails in milliseconds rather
        // than after every downstream server has started - and fails rather than
        // guessing. Checked when listing too, so list-upstream validates the same
        // launcher command line it will later be served with.
        ServeOptions serve;
        try
        {
            serve = ServeOptions.Parse(args, Environment.GetEnvironmentVariable(ServeOptions.TokenVariable));
        }
        catch (ServeOptionsException ex)
        {
            throw new CommandFailedException(2, ex.Message);
        }

        // --injection-classifier turns on the LLM second stage of the injection
        // scanner with its defaults (confirm mode, Haiku, ANTHROPIC_API_KEY) when
        // the policy does not configure it. A policy `classifier:` block always
        // wins, including one that says `mode: off`: the file is the reviewed,
        // committed statement of intent, and a flag in a launcher config should
        // not be able to quietly override it.
        var classifierFlag = args.Contains("--injection-classifier", StringComparer.Ordinal);

        // Where the sandboxed filesystem server is allowed to operate.
        var sandbox = Environment.GetEnvironmentVariable("GUARDRAILS_SANDBOX")
                      ?? Path.Combine(Path.GetTempPath(), "guardrails-sandbox");
        Directory.CreateDirectory(sandbox);

        // Where the audit log lands.
        var auditPath = CliPaths.ConfigPath("GUARDRAILS_AUDIT", "audit.jsonl");

        // Configured like the host's own logging, so a log line looks the same
        // whichever of the two wrote it.
        var loggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(
            logging => CliLogging.ToStandardError(logging, listing));

        // Everything created from here on is owned by the startup once it is
        // returned; until then, a failure has to release it here.
        UpstreamRegistry? upstream = null;
        JsonlAuditSink? audit = null;
        HttpClient? classifierHttp = null;
        try
        {
            // Connect to every downstream server and cache the tools they
            // advertise. Disposing the registry shuts every spawned child down.
            upstream = await UpstreamRegistry.ConnectAsync(
                DefaultUpstreams.Create(sandbox),
                loggerFactory);

            // Created after the registry so it is disposed BEFORE it: the sink
            // drains its queue while the tool calls that feed it are finished.
            audit = new JsonlAuditSink(
                auditPath, logger: loggerFactory.CreateLogger<JsonlAuditSink>());

            // One client for the life of the process, as HttpClient is designed
            // to be used. Infinite timeout because the injection gate owns the
            // classifier deadline; two competing timeouts would make "timed out"
            // mean two different things. Created unconditionally because it is
            // cheap and opens no connection until used.
            classifierHttp = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };

            var policyPath = CliPaths.ConfigPath("GUARDRAILS_POLICY", "policy.yaml");
            var (document, policy, budgets, injection, scanner, secrets) =
                LoadPolicy(policyPath, classifierFlag, classifierHttp);

            // A valid policy can still ask for something the chosen transport
            // cannot do: a session budget over stateless HTTP would quietly
            // become one pool shared by every client. Exit code 2 like the other
            // transport refusals, because the policy is fine - it is the
            // combination with --transport that is not.
            try
            {
                serve.EnsureEnforceable(budgets);
            }
            catch (ServeOptionsException ex)
            {
                throw new CommandFailedException(2, $"Policy file '{policyPath}': {ex.Message}");
            }

            var toolMetadata = ScanToolDefinitions(injection, upstream, loggerFactory);

            return new ProxyStartup(
                serve,
                loggerFactory,
                upstream,
                audit,
                classifierHttp,
                policyPath,
                document,
                policy,
                budgets,
                scanner,
                secrets,
                toolMetadata);
        }
        catch
        {
            // Reverse order of creation, as `await using` would have unwound.
            classifierHttp?.Dispose();
            if (audit is not null)
            {
                await audit.DisposeAsync();
            }

            if (upstream is not null)
            {
                await upstream.DisposeAsync();
            }

            loggerFactory.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Loads the policy and builds the gates it configures.
    /// </summary>
    /// <remarks>
    /// A missing file is not an error: no policy means pure passthrough with
    /// audit logging, which is the adoption story. A MALFORMED file is fatal -
    /// failing open on a broken security policy is exactly the wrong default.
    /// </remarks>
    private static (
        PolicyDocument Document,
        PolicyEvaluator Policy,
        BudgetPolicy Budgets,
        ScannerSettings Injection,
        InjectionGate Scanner,
        SecretGate Secrets) LoadPolicy(string policyPath, bool classifierFlag, HttpClient classifierHttp)
    {
        try
        {
            var document = PolicyLoader.LoadFromFileOrEmpty(policyPath);

            var policy = new PolicyEvaluator(document);
            var budgets = document.EffectiveBudgets;

            // On by default, including with no policy file at all: a result
            // scanner that has to be switched on protects nobody, and annotating
            // cannot break a call.
            var injection = document.EffectiveScanners.EffectiveInjection;

            if (classifierFlag && injection.Classifier is null)
            {
                injection = injection with { Classifier = ClassifierSettings.Default };
            }

            // Also on by default. Out of the box it changes no call - arguments
            // are forwarded as sent and only the audit log is scrubbed - but it
            // does redact secrets from results, because a key the model has read
            // cannot be unread.
            var secretSettings = document.EffectiveScanners.EffectiveSecrets;
            var secrets = new SecretGate(secretSettings);

            // The classifier is opt-in and off by default: it sends tool output
            // to a third party and costs money per call. A missing API key is a
            // startup error (PolicyException, caught below) rather than a
            // classifier that silently fails on every call. It runs inside the
            // secret gate, so it redacts for itself before anything leaves the
            // process.
            var scanner = injection.UsesClassifier
                ? new InjectionGate(
                    injection,
                    new RedactingInjectionClassifier(
                        AnthropicInjectionClassifier.Create(
                            injection.Classifier!,
                            classifierHttp,
                            Environment.GetEnvironmentVariable),
                        secretSettings.IncludePii))
                : new InjectionGate(injection);

            return (document, policy, budgets, injection, scanner, secrets);
        }
        catch (PolicyException ex)
        {
            throw new CommandFailedException(1, $"Invalid policy file '{policyPath}': {ex.Message}");
        }
    }

    /// <summary>Scans the tool definitions, once, and logs what was flagged.</summary>
    /// <remarks>
    /// Descriptions and schemas from tools/list are read by the model as if they
    /// were instructions, before any call has happened - "tool poisoning" - and
    /// the result scanner never sees them. The registry fetched them once at
    /// connect time, so they are scanned once here and the outcome is what
    /// tools/list serves and what the policy filter consults for every call.
    /// Heuristics only; see ToolMetadataGate for why the classifier is not asked.
    /// </remarks>
    private static ToolMetadataGate ScanToolDefinitions(
        ScannerSettings injection, UpstreamRegistry upstream, ILoggerFactory loggerFactory)
    {
        var toolMetadata = ToolMetadataGate.Build(
            injection,
            upstream.Connections.SelectMany(connection =>
                connection.Tools.Select(tool => (connection.Name, tool.ProtocolTool))));

        // Logged in list-upstream mode too (its level is Warning), because that
        // is the command an operator runs to see what a server advertises - and
        // the place a false positive should be found, before it hides a tool in
        // production.
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

        return toolMetadata;
    }

    public async ValueTask DisposeAsync()
    {
        // Reverse order of creation: the audit sink drains before the registry
        // shuts the downstream servers down, and the logger outlives both.
        ClassifierHttp.Dispose();
        await Audit.DisposeAsync();
        await Upstream.DisposeAsync();
        LoggerFactory.Dispose();
    }
}
