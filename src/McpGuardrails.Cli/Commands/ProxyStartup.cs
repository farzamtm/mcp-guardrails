using McpGuardrails.Core.Audit;
using McpGuardrails.Core.Budget;
using McpGuardrails.Core.Hosting;
using McpGuardrails.Core.Pins;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Scanners;
using McpGuardrails.Core.Upstream;
using Microsoft.Extensions.Logging;

namespace McpGuardrails.Cli.Commands;

/// <summary>
/// What serving and listing have in common: the command line checked, every
/// downstream server connected, the policy loaded, the tool definitions
/// scanned and compared with their pins.
/// </summary>
/// <remarks>
/// list-upstream runs exactly this and stops, so what it prints is what the
/// proxy would serve - including the effect of the metadata scanner, pin
/// changes and a policy that fails to load.
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
        ToolMetadataGate toolMetadata,
        PinStartup pins)
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
        Pins = pins;
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

    /// <summary>The pin comparison, and the gate built from it.</summary>
    public PinStartup Pins { get; }

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

        // Where calls go: the servers file, or the built-in filesystem server
        // when there is none. Loaded and validated in full before anything is
        // spawned, so every mistake in the file is reported at once.
        var servers = LoadServers(args);

        // Where the audit log lands.
        var auditPath = CliPaths.ConfigPath("GUARDRAILS_AUDIT", "audit.jsonl");

        // Configured like the host's own logging, so a log line looks the same
        // whichever of the two wrote it.
        var loggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(
            logging => CliLogging.ToStandardError(logging, listing));

        // Warnings are logged in list-upstream mode too: it is the command an
        // operator runs to check a new servers file, and where the environment
        // isolation notice should first be seen.
        var serversLog = loggerFactory.CreateLogger("McpGuardrails.Servers");
        foreach (var warning in servers.Warnings)
        {
            serversLog.LogWarning("{Warning}", warning);
        }

        // Everything created from here on is owned by the startup once it is
        // returned; until then, a failure has to release it here.
        UpstreamRegistry? upstream = null;
        JsonlAuditSink? audit = null;
        HttpClient? classifierHttp = null;
        try
        {
            // Connect to every downstream server and cache the tools they
            // advertise. Disposing the registry shuts every spawned child down.
            try
            {
                upstream = await UpstreamRegistry.ConnectAsync(servers.Servers, loggerFactory);
            }
            catch (UpstreamConnectionException ex)
            {
                // Fatal unless the server is marked optional: a proxy serving a
                // subset of the tools the operator configured is a tool set
                // nobody reviewed.
                throw new CommandFailedException(1, $"{ex.Message} Mark it 'optional: true' to start without it.");
            }

            foreach (var missing in upstream.Unavailable)
            {
                serversLog.LogWarning(
                    "Optional upstream server '{Server}' is unavailable and its tools are absent this session: {Reason}",
                    missing.Name,
                    missing.Reason);
            }

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
            var pins = CheckPins(document, policyPath, upstream, toolMetadata, listing, loggerFactory);

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
                toolMetadata,
                pins);
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
    /// The servers to connect: from the servers file when there is one, else the
    /// built-in filesystem server.
    /// </summary>
    private static ServersLoadResult LoadServers(string[] args)
    {
        var path = CliServers.Path(args);

        if (path is null)
        {
            // Where the sandboxed filesystem server is allowed to operate.
            var sandbox = Environment.GetEnvironmentVariable("GUARDRAILS_SANDBOX")
                          ?? Path.Combine(Path.GetTempPath(), "guardrails-sandbox");
            Directory.CreateDirectory(sandbox);

            return new ServersLoadResult(DefaultUpstreams.Create(sandbox), [], [], []);
        }

        var result = ServersLoader.LoadFile(path, CliHost.Environment);
        if (!result.IsValid)
        {
            throw new CommandFailedException(
                1,
                $"Invalid servers file '{path}':{Environment.NewLine}" +
                string.Join(Environment.NewLine, result.Errors.Select(e => $"  - {e}")));
        }

        return result;
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

    /// <summary>
    /// Compares every connected server's tools with the pins file, pins the
    /// servers seen for the first time, and builds the gate.
    /// </summary>
    /// <remarks>
    /// Listing compares but never writes: list-upstream is how an operator looks
    /// at a server before trusting it, and looking should not be what trusts it.
    /// Serving is what pins on first use.
    ///
    /// A pins file that exists but cannot be read is fatal in every mode but off.
    /// Treating it as empty would re-pin whatever every server serves now, which
    /// is the one thing pinning exists to refuse. A file that cannot be written
    /// on first use is fatal under block, where the operator asked for changes to
    /// be withheld and a pin that was never saved can never withhold anything,
    /// and a warning under warn.
    /// </remarks>
    private static PinStartup CheckPins(
        PolicyDocument document,
        string policyPath,
        UpstreamRegistry upstream,
        ToolMetadataGate toolMetadata,
        bool listing,
        ILoggerFactory loggerFactory)
    {
        var settings = document.EffectiveScanners.EffectivePins;
        var path = PinsFile.ResolvePath(
            settings, policyPath, Environment.GetEnvironmentVariable, CliHost.Environment.HomeDirectory);

        if (settings.IsOff)
        {
            return new PinStartup(settings, path, null, PinCheckResult.None, false,
                ToolPinGate.Build(settings, [], toolMetadata.Tools));
        }

        var log = loggerFactory.CreateLogger<ToolPinGate>();

        PinsDocument? existing;
        try
        {
            existing = PinsFile.Load(path);
        }
        catch (PinsException ex)
        {
            throw new CommandFailedException(1, ex.Message);
        }

        var result = PinCheck.Run(
            existing, upstream.Connections.Select(PinSubject.From), DateTimeOffset.UtcNow);

        var saved = false;
        if (!listing && result.DocumentChanged)
        {
            try
            {
                PinsFile.Save(path, result.Document);
                saved = true;
            }
            catch (PinsException ex) when (settings.EffectiveMode is PinMode.Warn)
            {
                log.LogWarning(
                    "{Message} The new servers' tools are not pinned, so a change to them will not be noticed on the next start.",
                    ex.Message);
            }
            catch (PinsException ex)
            {
                throw new CommandFailedException(
                    1, $"{ex.Message} 'scanners.pins.mode: block' needs a pins file it can write.");
            }
        }

        var gate = ToolPinGate.Build(settings, result.Reports, toolMetadata.Tools);

        foreach (var report in result.Reports.Where(r => r.FirstSeen))
        {
            if (listing)
            {
                log.LogWarning(
                    "Server '{Server}' has no pins yet; its {Count} tools will be pinned the first time the proxy serves.",
                    report.Server,
                    report.Current.Count);
            }
            else if (saved)
            {
                log.LogInformation("Pinned the {Count} tools of server '{Server}' in {Path}.", report.Current.Count, report.Server, path);
            }
        }

        foreach (var report in result.Reports.Where(r => r.IdentityChanged))
        {
            log.LogWarning(
                "Server '{Server}' is not the program it was pinned from (pinned from: {Pinned}; now: {Current}). Review with 'pins diff {Server}'.",
                report.Server,
                report.PinnedHint,
                report.CurrentHint,
                report.Server);
        }

        foreach (var finding in gate.Findings)
        {
            log.LogWarning(
                "Tool '{Tool}': {Explanation}; {Action}. Review with 'pins diff {Server} {DownstreamTool}', then 'pins accept'.",
                finding.Tool,
                finding.Explain(),
                finding.Effect switch
                {
                    PinEffect.Blocked => "withheld from tools/list and calls to it are refused",
                    PinEffect.Annotated => "its description is prefixed with a warning",
                    _ => "advertised unchanged, as on_new_tool: allow says",
                },
                finding.Server,
                finding.DownstreamTool);
        }

        foreach (var report in result.Reports.Where(r => r.Removed.Count > 0))
        {
            log.LogWarning(
                "Server '{Server}' no longer serves pinned tools: {Tools}.",
                report.Server,
                string.Join(", ", report.Removed));
        }

        return new PinStartup(settings, path, existing, result, saved, gate);
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

/// <summary>What startup learned from the pins file.</summary>
/// <param name="Settings">The policy's pin settings.</param>
/// <param name="Path">Where the pins file is.</param>
/// <param name="Existing">The file as loaded, or null when there was none, or pinning is off.</param>
/// <param name="Result">The comparison; empty when pinning is off.</param>
/// <param name="Saved">True when first-use pins were written.</param>
/// <param name="Gate">What tools/list serves and what calls are refused.</param>
internal sealed record PinStartup(
    PinSettings Settings,
    string Path,
    PinsDocument? Existing,
    PinCheckResult Result,
    bool Saved,
    ToolPinGate Gate);
