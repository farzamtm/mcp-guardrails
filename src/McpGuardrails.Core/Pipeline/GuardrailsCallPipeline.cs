using System.Diagnostics;
using McpGuardrails.Core.Access;
using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Audit;
using McpGuardrails.Core.Budget;
using McpGuardrails.Core.Pins;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Scanners;
using McpGuardrails.Core.Upstream;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Pipeline;

/// <summary>
/// Everything that happens to one <c>tools/call</c> between the client and the
/// downstream server: audit, the gates, redaction, result scanning, the forward.
/// </summary>
/// <remarks>
/// Lives in Core rather than in the CLI's ServeCommand because this is where the
/// decisions are, and the CLI is excluded from coverage. The order of the layers
/// is the security design - a policy denial must never reach an approver, a
/// credential must be refused before a human is asked, budget must only be spent
/// on a call that is really going out - and an order nobody can unit-test is an
/// order a refactor can silently break. The host registers
/// <see cref="InvokeAsync"/> as its one call filter and <see cref="ForwardAsync"/>
/// as its call handler; nothing else about a call is decided there.
///
/// The layers nest like middleware, outermost first:
///
///     audit -> gates -> redaction -> result scanner -> forward
///
/// Audit is outermost so it records calls the inner layers refuse. The result
/// scanner is innermost so it sees exactly what the server returned and never
/// the proxy's own refusals.
/// </remarks>
public sealed class GuardrailsCallPipeline
{
    /// <summary>
    /// The name a call is known by when the client did not send one.
    /// </summary>
    /// <remarks>
    /// One constant for every layer on purpose: if audit and policy disagreed,
    /// the log and the policy would describe different calls, in exactly the
    /// malformed-traffic case where someone reading the log most needs to trust it.
    /// </remarks>
    public const string UnnamedTool = "(missing)";

    private readonly UpstreamRegistry _upstream;
    private readonly IAuditSink _audit;
    private readonly ToolCallTelemetry _telemetry;
    private readonly PolicyEvaluator _policy;
    private readonly ToolMetadataGate _toolMetadata;
    private readonly ToolPinGate _toolPins;
    private readonly SecretGate _secrets;
    private readonly ArgumentGate _arguments;
    private readonly BudgetGate _budget;
    private readonly InjectionGate _scanner;
    private readonly IApprovalChannel? _webhook;
    private readonly IApprovalChannel? _localUi;
    private readonly bool _explain;

    /// <param name="upstream">Resolves names for the log, the policy and the forward.</param>
    /// <param name="audit">Where every call is recorded, refused or not.</param>
    /// <param name="telemetry">Spans and metrics; inert when nothing listens.</param>
    /// <param name="policy">The rules.</param>
    /// <param name="toolMetadata">Refuses tools withheld from tools/list for looking poisoned.</param>
    /// <param name="toolPins">Refuses tools withheld from tools/list for differing from their pins.</param>
    /// <param name="secrets">Argument blocking and redaction, result redaction.</param>
    /// <param name="arguments">The argument attack detectors.</param>
    /// <param name="budget">Caps on what an approved call may spend.</param>
    /// <param name="scanner">The prompt-injection result scanner.</param>
    /// <param name="webhook">The out-of-band approver, when the policy configures one.</param>
    /// <param name="explain">
    /// Append the decision trail to refusals. Off by default because building the
    /// trail allocates on a path every tool call takes.
    /// </param>
    /// <param name="localUi">The local UI's approval inbox, for <c>mode: local_ui</c> rules.</param>
    public GuardrailsCallPipeline(
        UpstreamRegistry upstream,
        IAuditSink audit,
        ToolCallTelemetry telemetry,
        PolicyEvaluator policy,
        ToolMetadataGate toolMetadata,
        ToolPinGate toolPins,
        SecretGate secrets,
        ArgumentGate arguments,
        BudgetGate budget,
        InjectionGate scanner,
        IApprovalChannel? webhook = null,
        bool explain = false,
        IApprovalChannel? localUi = null)
    {
        ArgumentNullException.ThrowIfNull(upstream);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(telemetry);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(toolMetadata);
        ArgumentNullException.ThrowIfNull(toolPins);
        ArgumentNullException.ThrowIfNull(secrets);
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(budget);
        ArgumentNullException.ThrowIfNull(scanner);

        _upstream = upstream;
        _audit = audit;
        _telemetry = telemetry;
        _policy = policy;
        _toolMetadata = toolMetadata;
        _toolPins = toolPins;
        _secrets = secrets;
        _arguments = arguments;
        _budget = budget;
        _scanner = scanner;
        _webhook = webhook;
        _localUi = localUi;
        _explain = explain;
    }

    /// <summary>
    /// A result the model reads as a failed tool call.
    /// </summary>
    /// <remarks>
    /// A tool ERROR, not a JSON-RPC protocol error, for every refusal the proxy
    /// produces. Protocol errors are for malformed traffic; "refused" and "no
    /// such tool" are results the model should read and adapt to, which is also
    /// why the texts are written for the model rather than for a log file.
    /// </remarks>
    public static CallToolResult Error(string text) => new()
    {
        IsError = true,
        Content = [new TextContentBlock { Text = text }],
    };

    /// <summary>Runs one call through every layer.</summary>
    /// <param name="parameters">The call as the client sent it. Arguments may be redacted in place.</param>
    /// <param name="inBand">
    /// Who a <c>mode: in_band</c> approval is put to - the client, or nobody on a
    /// transport that cannot ask it. Per call because it depends on the session.
    /// </param>
    /// <param name="forward">
    /// The innermost step: in the host, the SDK's call handler, which is
    /// <see cref="ForwardAsync"/>.
    /// </param>
    /// <param name="caller">
    /// Who made the call, when an access token said so; null over stdio and
    /// over HTTP without <c>access.oauth</c>.
    /// </param>
    /// <param name="cancellationToken">The client's cancellation.</param>
    public ValueTask<CallToolResult> InvokeAsync(
        CallToolRequestParams? parameters,
        IApprovalChannel inBand,
        Func<CancellationToken, ValueTask<CallToolResult>> forward,
        CallerIdentity? caller = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inBand);
        ArgumentNullException.ThrowIfNull(forward);

        return AuditAsync(
            parameters,
            gated => GateAsync(
                parameters,
                inBand,
                redacting => RedactAsync(
                    parameters,
                    scanning => ScanAsync(parameters, forward, scanning),
                    redacting),
                caller,
                gated),
            caller,
            cancellationToken);
    }

    /// <summary>
    /// Routes a call that every gate allowed to the server that owns the tool.
    /// </summary>
    /// <remarks>
    /// Everything before this is "on the way in", everything after it "on the way
    /// back" - the two halves of the interceptor pipeline.
    /// </remarks>
    public async ValueTask<CallToolResult> ForwardAsync(
        CallToolRequestParams? parameters,
        CancellationToken cancellationToken = default)
    {
        var requestedName = parameters?.Name;

        if (requestedName is not null && _upstream.TryGetUnavailable(requestedName, out var unavailable))
        {
            return Error(
                $"Tool '{requestedName}' belongs to server '{unavailable.Name}', which is not available in " +
                $"this session. {unavailable.Reason} Tell the user; calling it again will not help.");
        }

        if (requestedName is null ||
            !_upstream.TryResolve(requestedName, out var connection, out var downstreamName))
        {
            return Error($"Unknown tool '{requestedName}'.");
        }

        try
        {
            return await connection.Client.CallToolAsync(
                new CallToolRequestParams
                {
                    Name = downstreamName,
                    Arguments = parameters?.Arguments,
                },
                cancellationToken);
        }
        catch (Exception ex) when (UpstreamNeedsOperatorException.Find(ex) is { } needed)
        {
            // E.g. a login that expired mid-session and could not be refreshed. A
            // tool error rather than a protocol error, so the model reads it and
            // stops, and the audit log records a failed call with this reason.
            return Error($"Refused '{requestedName}': {needed.Message} Tell the user; calling it again will not help.");
        }
    }

    private static string ToolName(CallToolRequestParams? parameters) =>
        parameters?.Name ?? UnnamedTool;

    /// <summary>The outermost layer: one audit record and one span per call.</summary>
    internal async ValueTask<CallToolResult> AuditAsync(
        CallToolRequestParams? parameters,
        Func<CancellationToken, ValueTask<CallToolResult>> next,
        CallerIdentity? caller,
        CancellationToken cancellationToken)
    {
        // Opens the per-call scope that lets the inner layers report their
        // decisions back up to this one. See GuardrailsCallScope for why a
        // mutable holder is required rather than a plain AsyncLocal value.
        using var scope = GuardrailsCallScope.Begin();

        var toolName = ToolName(parameters);

        // Fail closed: with the log broken, a forwarded call would leave no
        // evidence at all. Refuse BEFORE forwarding - the sink would throw
        // afterwards anyway, but only once the downstream action had run.
        if (_audit.IsFaulted)
        {
            return Error(
                $"Refused '{toolName}': the guardrails audit log cannot be written, " +
                "so no tool calls are being forwarded. This needs an operator.");
        }

        // Resolved purely to enrich the log. The forward resolves again to
        // actually route; duplicating a dictionary lookup is cheaper than
        // coupling the two concerns together.
        var resolved = _upstream.TryResolve(toolName, out var connection, out var downstreamName);
        var server = resolved ? connection.Name : null;
        var downstreamTool = resolved ? downstreamName : null;

        // Opened before `next` so policy, approval and the downstream call all
        // run inside the span, and the SDK's client span for the forward nests
        // under it rather than becoming a sibling.
        using var span = _telemetry.Start(toolName, server, downstreamTool);

        // Scanned here, before anything runs, rather than taken from the layers
        // inside: a call the policy refuses never reaches them, and its arguments
        // are exactly as likely to hold a key. Before `next`, too, because
        // redaction may rewrite the arguments in place and this must see what
        // the model actually sent.
        var arguments = _secrets.ScanArguments(parameters?.Arguments);

        // Stopwatch timestamps rather than DateTime subtraction: a monotonic
        // clock, so an NTP correction mid-call cannot produce a negative duration.
        var startedAt = Stopwatch.GetTimestamp();

        CallToolResult? result = null;
        Exception? thrown = null;

        try
        {
            result = await next(cancellationToken);
            return result;
        }
        catch (Exception ex)
        {
            // Record the failure, then rethrow. Audit observes; it must never
            // change the outcome of a call.
            thrown = ex;
            throw;
        }
        finally
        {
            var elapsed = Stopwatch.GetElapsedTime(startedAt);
            var record = ToAuditRecord(
                toolName, server, downstreamTool, caller, arguments, scope, elapsed, result, thrown);

            // Same duration and decision as the record, so a dashboard and the
            // log never disagree about the same call.
            span.Complete(scope.Decision, elapsed, result?.IsError is true, thrown);

            // CancellationToken.None on purpose: if the caller cancelled, we
            // still want the record. Losing the evidence of an aborted call is
            // exactly the case an audit log exists for.
            await _audit.WriteAsync(record, CancellationToken.None);
        }
    }

    private AuditRecord ToAuditRecord(
        string toolName,
        string? server,
        string? downstreamTool,
        CallerIdentity? caller,
        ArgumentScan arguments,
        GuardrailsCallScope scope,
        TimeSpan elapsed,
        CallToolResult? result,
        Exception? thrown)
    {
        var decision = scope.Decision;
        var scan = scope.Scan;
        var failure = thrown is null ? null : $"{thrown.GetType().Name}: {thrown.Message}";

        return new AuditRecord
        {
            Timestamp = DateTimeOffset.UtcNow,
            Event = "tool_call",
            Tool = toolName,
            Server = server,
            DownstreamTool = downstreamTool,
            Principal = caller?.Principal,
            Arguments = arguments.Redacted,
            Decision = decision?.Verdict.ToWireName(),
            Rule = decision?.RuleName,
            DecisionReason = decision?.Reason,
            Approval = decision?.ApprovalResult?.ToWireName(),
            // The gate asked with the rule's settings, or the defaults when the
            // call was escalated by a scanner rather than a rule.
            ApprovalChannel = decision?.ApprovalResult is null
                ? null
                : (decision.Approval ?? ApprovalSettings.Default).EffectiveMode.ToWireName(),
            // Null unless something matched, so a clean result stays one narrow
            // line and `jq 'select(.scanner_hits)'` is the whole query for "show
            // me what the scanner caught".
            ScannerHits = scan is { Effect: not ScanEffect.None } ? scan.Heuristics : null,
            ScannerAction = scan?.Describe(),
            ScannerStructuredContentWithheld = scan is { StructuredContentWithheld: true } ? true : null,
            Classifier = scan?.Classifier?.Describe(),
            ClassifierTruncated = scan?.Classifier is { Truncated: true } ? true : null,
            ClassifierError = scan?.Classifier?.Error,
            ArgumentSecrets = arguments.Report.IsClean ? null : arguments.Report.Detectors,
            ArgumentSecretsAction = _secrets.DescribeArguments(arguments, decision),
            ArgumentHits = scope.Arguments is { Findings.IsClean: false } found ? found.Findings.Detectors : null,
            ArgumentHitsAction = scope.Arguments?.Describe(),
            ResultSecrets = scope.Redaction is { Effect: not RedactionEffect.None } redaction
                ? redaction.Report.Detectors
                : null,
            ResultSecretsAction = scope.Redaction?.Describe(),
            DurationMs = elapsed.TotalMilliseconds,
            // No result means the call threw, which is an error by definition.
            IsError = result is null || result.IsError is true,
            Error = failure,
        };
    }

    /// <summary>
    /// Policy, tool metadata, tool pins, argument secrets, argument detectors,
    /// approval and budget - in that order.
    /// </summary>
    /// <remarks>
    /// Inside audit, so when this refuses a call by not invoking <c>next</c>,
    /// nothing downstream runs but the attempt is still recorded.
    /// </remarks>
    internal async ValueTask<CallToolResult> GateAsync(
        CallToolRequestParams? parameters,
        IApprovalChannel inBand,
        Func<CancellationToken, ValueTask<CallToolResult>> next,
        CallerIdentity? caller,
        CancellationToken cancellationToken)
    {
        var toolName = ToolName(parameters);

        // The tool definition carries the annotations rules match on. An unknown
        // name yields null, and policy still runs: a catch-all deny has to cover
        // calls the proxy was going to reject anyway, or the audit log and the
        // policy would tell different stories.
        _upstream.TryGetTool(toolName, out var tool);

        // The owning server is not matched on, but an out-of-band approver shows
        // it: "fs" or "prod-db" changes what a human says to a delete.
        //
        // Resolving also tells the budget whether the call can be forwarded at
        // all: an unknown tool ends at the forward's error, so it is not charged.
        // Policy, secrets and approval still see it, and audit still records it.
        // The registry is immutable after startup, so the forward cannot resolve
        // a name this lookup did not - no call is forwarded uncharged.
        var resolved = _upstream.TryResolve(toolName, out var owner, out _);
        var server = resolved ? owner.Name : null;

        var facts = PolicyFacts.ForCall(toolName, parameters, tool, server, caller);

        // Seven gates, in this order, and the order is the design.
        //
        // The policy decides whether the call is permitted at all. The metadata
        // scanner refuses a tool it withheld from tools/list - refused, not merely
        // left off the list, because a client with a stale list or a model that
        // guessed the name must not reach it - and the pin gate does the same for
        // a tool whose definition changed since it was reviewed, naming both
        // reasons when both apply. The secret scanner, under
        // `arguments: block`, refuses a call carrying a credential - before
        // approval, so nobody is asked to approve a call that will be refused,
        // and so a human who approves a harmless-looking write is not also
        // approving the key buried in its content. The argument detectors come
        // next, for the same reason and one more: under `action: approve` they
        // turn an allowed call into a question, which only works before the
        // question is asked. Approval turns a
        // 'require_approval' verdict into a real answer from a real human - which
        // can only happen before the budget runs, because a call waiting on a
        // person has not been forwarded and must not be charged. Budget then
        // decides whether there is anything left to spend on the call that is
        // finally going out.
        var decision = _policy.Evaluate(facts, _explain);
        decision = _toolMetadata.Apply(decision, toolName);
        decision = _toolPins.Apply(decision, toolName);
        decision = _secrets.Apply(decision, parameters?.Arguments);

        var arguments = _arguments.Apply(decision, toolName, parameters?.Arguments);
        GuardrailsCallScope.RecordArguments(arguments);
        decision = arguments.Decision;

        // Recorded now as well as at the end, because the approval wait can end
        // in cancellation - the client hanging up - which propagates as an
        // exception past the line below. The audit record of an abandoned call
        // should still say what had been decided (typically require_approval),
        // not carry no decision at all.
        GuardrailsCallScope.RecordDecision(decision);

        decision = await ApprovalGate.ApplyAsync(
            decision,
            facts,
            new ApprovalChannelRouter(inBand, _webhook, _localUi),
            cancellationToken);

        decision = _budget.Apply(decision, resolved, caller?.Principal);

        GuardrailsCallScope.RecordDecision(decision);

        if (!decision.IsBlocked)
        {
            return await next(cancellationToken);
        }

        var text = decision.ToModelMessage();

        // The evaluator only builds a trail when asked to explain, and later gates
        // only extend one that exists, so its presence is the --explain switch.
        if (decision.Trail is { Count: > 0 } trail)
        {
            text += "\n\nDecision trail:\n  " + string.Join("\n  ", trail);
        }

        return Error(text);
    }

    /// <summary>
    /// Secret redaction: forwarded arguments on the way in, the result on the way back.
    /// </summary>
    /// <remarks>
    /// After the gates, so the policy judged the real arguments and only the copy
    /// that leaves is redacted. Outside the result scanner, so it is the last
    /// thing to touch a result before the model reads it - and, like that
    /// scanner, it never sees the proxy's own refusals.
    /// </remarks>
    internal async ValueTask<CallToolResult> RedactAsync(
        CallToolRequestParams? parameters,
        Func<CancellationToken, ValueTask<CallToolResult>> next,
        CancellationToken cancellationToken)
    {
        if (parameters is not null &&
            _secrets.RedactForwarded(parameters.Arguments) is { } redacted)
        {
            parameters.Arguments = redacted;
        }

        var result = await next(cancellationToken);

        var outcome = _secrets.Inspect(result, ToolName(parameters));

        GuardrailsCallScope.RecordRedaction(outcome);

        return outcome.Result;
    }

    /// <summary>The prompt-injection scanner, the first layer on the way back.</summary>
    internal async ValueTask<CallToolResult> ScanAsync(
        CallToolRequestParams? parameters,
        Func<CancellationToken, ValueTask<CallToolResult>> next,
        CancellationToken cancellationToken)
    {
        var result = await next(cancellationToken);

        // Async because the optional classifier is a network call. Without one
        // configured this completes synchronously. Classifier failures never
        // surface here - the gate turns them into "the heuristic verdict stands"
        // and records why.
        var outcome = await _scanner.InspectAsync(result, ToolName(parameters), cancellationToken);

        GuardrailsCallScope.RecordScan(outcome);

        return outcome.Result;
    }
}
