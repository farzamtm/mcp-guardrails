using McpGuardrails.Core.Access;
using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Audit;
using McpGuardrails.Core.Budget;
using McpGuardrails.Core.Hosting;
using McpGuardrails.Core.LocalUi;
using McpGuardrails.Core.Pins;
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

namespace McpGuardrails.Cli.Commands;

/// <summary>
/// The default command: serves the aggregated, guardrailed tools over stdio or
/// Streamable HTTP until the client goes away.
/// </summary>
/// <remarks>
/// The composition root. It only wires the MCP server half to the pipeline;
/// what happens to a tool call lives in GuardrailsCallPipeline in Core.
/// </remarks>
internal sealed class ServeCommand : ICliCommand
{
    public async Task<int> RunAsync(string[] args)
    {
        // --explain appends the policy decision trail to every denial, so "why
        // was this blocked?" is answerable without reading the rules. Off by
        // default: building the trail allocates on a path that runs for every
        // single tool call.
        var explain = args.Contains("--explain", StringComparer.Ordinal);

        // OpenTelemetry export is opt-in. Setting the standard OTLP endpoint
        // variable is itself the opt-in, so the proxy behaves like any other
        // OTel-instrumented process; --otel means "export to the default
        // collector on localhost". Off by default because a security tool should
        // not open network connections nobody asked for.
        var otel = args.Contains("--otel", StringComparer.Ordinal)
                   || !string.IsNullOrWhiteSpace(
                       Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT"));

        // Reported as the MCP server version and as the OTel service.version, so
        // a trace and a client's server list agree on what was running.
        var proxyVersion = ProxyVersion.Of(typeof(Program).Assembly);

        // Created unconditionally: with no exporter attached the span and
        // instruments are inert, and the audit filter does not need a second
        // code path. Declared first so it is disposed last.
        using var telemetry = new ToolCallTelemetry();

        await using var startup = await ProxyStartup.LoadAsync(args, listing: false);
        var serve = startup.Serve;
        var document = startup.Document;
        var toolMetadata = startup.ToolMetadata;
        var toolPins = startup.Pins.Gate;

        // Both builders implement IHostApplicationBuilder, so everything below -
        // logging, and above all the MCP server with its guardrail filters - is
        // configured once, through the interface, for whichever transport was
        // chosen. Only the listener differs. The slim builder because it is the
        // AOT-friendly one.
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

        // The default host logs to stdout, which is the JSON-RPC wire: clear the
        // default providers and force every log to stderr.
        builder.Logging.ClearProviders();
        CliLogging.ToStandardError(builder.Logging, listing: false);

        if (otel)
        {
            // Traces and metrics only, not logs. The proxy's log lines are for
            // the operator's terminal; exporting them would be a second,
            // unreviewed channel out of the process.
            //
            // "Experimental.ModelContextProtocol" is the MCP SDK's own source and
            // meter. Subscribing to it adds the semconv tools/call server span
            // above ours and a client span per downstream call beneath it, so one
            // trace shows the whole hop: client -> guardrails -> downstream server.
            //
            // Endpoint, protocol, headers, export intervals and OTEL_SDK_DISABLED
            // come from the standard OTEL_* environment variables, read by the
            // SDK. The exporter writes to the network, never to stdout, so the
            // JSON-RPC wire is not at risk.
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

        // -------------------------------------------------------------------
        // OAuth access tokens, if the policy configures 'access.oauth'.
        //
        // The issuer's signing keys are fetched now, before the listener opens:
        // a proxy that cannot validate any token would refuse every request, and
        // the operator should hear that the issuer is unreachable from the
        // startup error, not from a client's 401.
        // -------------------------------------------------------------------
        SigningKeyCache? signingKeys = null;
        OAuthAccessGuard? oauthGuard = null;

        if (serve.OAuth is { } oauth)
        {
            var accessLog = startup.LoggerFactory.CreateLogger("McpGuardrails.Access");
            foreach (var warning in oauth.Warnings)
            {
                accessLog.LogWarning("{Warning}", warning);
            }

            signingKeys = new SigningKeyCache(
                oauth,
                SigningKeyCache.CreateHandler(),
                logger: startup.LoggerFactory.CreateLogger<SigningKeyCache>());

            try
            {
                await signingKeys.InitializeAsync();
            }
            catch (OAuthException ex)
            {
                signingKeys.Dispose();
                throw new CommandFailedException(1, $"Policy file '{startup.PolicyPath}': {ex.Message}");
            }

            oauthGuard = new OAuthAccessGuard(oauth, new AccessTokenValidator(oauth, signingKeys));
        }

        using var signingKeysLifetime = signingKeys;

        // Where daily budget counters persist. An environment variable like the
        // audit and policy paths, not a policy key: the policy says what the
        // limits are, the deployment says where state lives - and two agents
        // sharing one policy file may well want separate daily budgets. Every
        // proxy pointed at the same file shares one budget. Only opened when
        // `budgets.daily` is configured.
        var budgetDbPath = CliPaths.ConfigPath("GUARDRAILS_BUDGET_DB", "budgets.db");

        // Captured so it can be disposed on exit; null when no daily cap is configured.
        SqliteBudgetStore? dailyStore = null;
        BudgetGate budget;

        try
        {
            // No `budgets:` section means an unlimited gate rather than no gate:
            // the call path is then the same whether or not anyone configured a
            // cap, so the configured path is not the one that only ever runs in
            // production.
            budget = BudgetGate.For(
                startup.Budgets,
                limits => dailyStore = new SqliteBudgetStore(budgetDbPath, limits));
        }
        catch (Exception ex) when (ex is SqliteException or IOException or UnauthorizedAccessException)
        {
            // Fatal, like a malformed policy: running without the daily cap the
            // operator asked for would be failing open.
            throw new CommandFailedException(1, $"Cannot open budget store '{budgetDbPath}': {ex.Message}");
        }

        using var dailyStoreLifetime = dailyStore;

        // One audit line per connected server, recording what it was launched
        // from, so the log says which program answered each later call.
        foreach (var connection in startup.Upstream.Connections)
        {
            await startup.Audit.WriteAsync(UpstreamAudit.Connected(connection, DateTimeOffset.UtcNow), CancellationToken.None);
        }

        // One audit line per flagged tool.
        foreach (var finding in toolMetadata.Findings)
        {
            await startup.Audit.WriteAsync(finding.ToAuditRecord(DateTimeOffset.UtcNow), CancellationToken.None);
        }

        // What pinning found: servers trusted on first use (only when the pins
        // were really written - a pin that was never saved was never created),
        // every tool that differs from its pin, and every pinned tool that is gone.
        foreach (var report in startup.Pins.Result.Reports)
        {
            if (report.FirstSeen && startup.Pins.Saved)
            {
                await startup.Audit.WriteAsync(PinAudit.Created(report, DateTimeOffset.UtcNow), CancellationToken.None);
            }

            foreach (var removed in PinAudit.Removed(report, DateTimeOffset.UtcNow))
            {
                await startup.Audit.WriteAsync(removed, CancellationToken.None);
            }
        }

        foreach (var finding in toolPins.Findings)
        {
            await startup.Audit.WriteAsync(PinAudit.Changed(finding, DateTimeOffset.UtcNow), CancellationToken.None);
        }

        // -------------------------------------------------------------------
        // The webhook approver, if the policy configures one.
        //
        // Built here, not in the shared startup, because this is the first point
        // that needs the signing secret: listing (and CI's example-policy check)
        // should work on a machine that does not hold it. Serving without it is
        // fatal, for the same reason a malformed policy is - a rule routed to an
        // approver we cannot authenticate to would deny every call, and the
        // operator should hear about it now rather than from the first refusal.
        // -------------------------------------------------------------------
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
                throw new CommandFailedException(1, $"Invalid policy file '{startup.PolicyPath}': {ex.Message}");
            }
        }

        using var webhookLifetime = webhook;

        // Who an in-band require_approval call is put to. Over stdio, the human
        // at the client via elicitation. Over stateless HTTP there is no channel
        // back to the client, so the answer is "nobody", given immediately - see
        // StatelessHttpApprovalChannel. A `mode: webhook` rule does not depend on
        // the client, so it works the same on either transport.
        Func<McpServer, IApprovalChannel> approvalChannel = serve.Transport is Transport.Http
            ? _ => StatelessHttpApprovalChannel.Instance
            : server => new ElicitationApprovalChannel(server, document.EffectiveScanners.EffectiveSecrets);

        // The local UI's inbox, for `mode: local_ui` rules. Always wired: it
        // costs nothing until a rule uses it, and it locates the UI afresh for
        // every question, so the UI can be started after the proxy, or restarted
        // while it runs.
        var uiRendezvousPath = CliPaths.ConfigPath(UiRendezvous.FileVariable, UiRendezvous.FileName);
        var localUi = new LocalUiApprovalChannel(
            () => File.Exists(uiRendezvousPath) ? UiRendezvous.Parse(File.ReadAllText(uiRendezvousPath)) : null,
            document.EffectiveScanners.EffectiveSecrets,
            WebhookApprovalChannel.CreateHandler);

        var pipeline = new GuardrailsCallPipeline(
            startup.Upstream,
            startup.Audit,
            telemetry,
            startup.Policy,
            toolMetadata,
            toolPins,
            startup.Secrets,
            new ArgumentGate(document.EffectiveScanners.EffectiveArguments),
            budget,
            startup.Scanner,
            webhook,
            explain,
            localUi);

        // -------------------------------------------------------------------
        // Serve the aggregated tools.
        //
        // Instead of registering tools of our own, we supply two handlers - the
        // merged tool list and the forward - and one call filter wrapped around
        // the forward that runs every guardrail. The filter is the only place
        // SDK request types meet the pipeline, which takes plain protocol DTOs
        // so it can be tested without a live session.
        // -------------------------------------------------------------------
        var mcp = builder.Services
            .AddMcpServer(options =>
            {
                options.ServerInfo = new Implementation { Name = "mcp-guardrails", Version = proxyVersion };

                // The caller is what HttpHost validated and attached to the HTTP
                // request, carried here by the SDK as the message's user; null
                // over stdio and without access.oauth.
                options.Filters.Request.CallToolFilters.Add(next => (request, cancellationToken) =>
                    pipeline.InvokeAsync(
                        request.Params,
                        approvalChannel(request.Server),
                        forwardToken => next(request, forwardToken),
                        CallerIdentity.FromClaimsPrincipal(request.User),
                        cancellationToken));
            })
            .WithListToolsHandler((_, _) =>
            {
                // Built once at startup, already qualified with the same namer
                // the call handler resolves through - so the client never sees a
                // tool it cannot invoke - already scanned and already compared
                // with its pins. A fresh list per request because the result DTO
                // is mutable and must not be shared between clients.
                var tools = toolPins.Tools.ToList();

                // The handler is synchronous, but the delegate returns ValueTask,
                // so wrap the finished value rather than paying for a state machine.
                return ValueTask.FromResult(new ListToolsResult { Tools = tools });
            })
            .WithCallToolHandler((request, cancellationToken) =>
                pipeline.ForwardAsync(request.Params, cancellationToken));

        if (web is not null)
        {
            // Stateless is the SDK default as of the 2026-07-28 revision; spelled
            // out because the approval behaviour above depends on it.
            mcp.WithHttpTransport(options => options.SessionMode = HttpServerSessionMode.Stateless);

            await HttpHost.RunAsync(web.Build(), serve, oauthGuard);
        }
        else
        {
            mcp.WithStdioServerTransport();

            await ((HostApplicationBuilder)builder).Build().RunAsync();
        }

        return 0;
    }
}
