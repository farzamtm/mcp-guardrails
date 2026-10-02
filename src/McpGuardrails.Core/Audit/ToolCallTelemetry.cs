using System.Diagnostics;
using System.Diagnostics.Metrics;
using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Audit;

/// <summary>
/// The OpenTelemetry half of "JSONL + OTel audit": a span per tool call and a
/// handful of metrics, emitted through the BCL's own tracing and metrics APIs.
/// </summary>
/// <remarks>
/// Core does not reference the OpenTelemetry SDK, on purpose. ActivitySource and
/// Meter live in System.Diagnostics, cost close to nothing when nobody is
/// listening, and are Native AOT safe. The SDK and its exporter are a CLI
/// concern, wired up only when an operator asks for them; until then this class
/// is a handful of null checks per call.
///
/// Privacy follows the audit log, and is stricter in one place. Nothing here
/// ever reads tool arguments: a trace backend is typically shared far more
/// widely than an audit file on the proxy's own disk, and has no redaction step.
/// Exception messages and decision reasons are left out for the same reason -
/// both can quote what the agent sent - so a span carries the exception TYPE
/// and the rule NAME, which is enough to find the matching audit line.
///
/// Attribute names follow the OpenTelemetry GenAI/MCP semantic conventions where
/// one exists (<c>gen_ai.tool.name</c>, <c>error.type</c>) and use the
/// <c>mcp_guardrails.</c> prefix where the concept is ours. The span does NOT
/// carry <c>mcp.method.name</c>: the MCP SDK already emits the semconv
/// <c>tools/call</c> server and client spans around this one, and a backend that
/// counts MCP operations by that attribute would count every call twice.
/// </remarks>
public sealed class ToolCallTelemetry : IDisposable
{
    /// <summary>The ActivitySource and Meter name an exporter subscribes to.</summary>
    public const string SourceName = "McpGuardrails";

    /// <summary>
    /// Stand-in for a tool name the proxy could not resolve, in metric tags.
    /// </summary>
    /// <remarks>
    /// The semconv spelling for "a value outside the known set". Metric tags must
    /// be low-cardinality, and the tool name in an unresolvable call is whatever
    /// the client typed - a client looping over random names would otherwise
    /// mint a new time series per call. Spans keep the real name, because a span
    /// is one event rather than a series.
    /// </remarks>
    public const string OtherTool = "_OTHER";

    /// <summary>The <c>error.type</c> value semconv assigns to an isError tool result.</summary>
    public const string ToolError = "tool_error";

    // Semconv buckets for MCP operation durations, so this histogram lines up
    // with the SDK's mcp.server.operation.duration on the same dashboard. The
    // default OTel buckets are milliseconds-shaped and useless for seconds.
    private static readonly double[] _durationBuckets =
        [0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 30, 60, 120, 300];

    private readonly Counter<long> _calls;
    private readonly Counter<long> _denials;
    private readonly Counter<long> _approvals;
    private readonly Histogram<double> _duration;

    /// <summary>Creates the source and instruments.</summary>
    /// <remarks>
    /// An instance rather than statics so each test can listen to its own
    /// source and meter without seeing measurements from tests running in
    /// parallel. The production process creates exactly one.
    /// </remarks>
    public ToolCallTelemetry()
    {
        ActivitySource = new ActivitySource(SourceName);
        Meter = new Meter(SourceName);

        _calls = Meter.CreateCounter<long>(
            "mcp_guardrails.tool_calls",
            unit: "{call}",
            description: "Tool calls seen by the proxy, by final decision.");

        _denials = Meter.CreateCounter<long>(
            "mcp_guardrails.denials",
            unit: "{call}",
            description: "Tool calls the proxy refused, by the guardrail and rule that refused them.");

        _approvals = Meter.CreateCounter<long>(
            "mcp_guardrails.approvals",
            unit: "{request}",
            description: "Times a human was asked to approve a call, by outcome.");

        _duration = Meter.CreateHistogram(
            "mcp_guardrails.tool_call.duration",
            unit: "s",
            description: "Time from the proxy receiving a tool call to answering it, guardrails included.",
            tags: null,
            advice: new InstrumentAdvice<double> { HistogramBucketBoundaries = _durationBuckets });
    }

    /// <summary>Source of the per-call spans.</summary>
    public ActivitySource ActivitySource { get; }

    /// <summary>Meter that owns the counters and the latency histogram.</summary>
    public Meter Meter { get; }

    /// <summary>
    /// Opens the span for one tool call. Call before anything else in the
    /// pipeline runs, so policy, approval and the downstream call nest inside it.
    /// </summary>
    /// <param name="tool">Client-visible tool name.</param>
    /// <param name="server">Owning downstream server, or null when unresolved.</param>
    /// <param name="downstreamTool">Tool name as the server knows it, when resolved.</param>
    public ToolCallSpan Start(string tool, string? server, string? downstreamTool)
    {
        ArgumentNullException.ThrowIfNull(tool);

        // A resolved name is from a fixed, advertised set and fine in a span name;
        // an unresolved one is free text from the client, so it stays out of the
        // name (backends index on it) and only appears as an attribute.
        var activity = ActivitySource.StartActivity(
            server is null ? "guardrails tools/call" : $"guardrails tools/call {tool}",
            ActivityKind.Internal);

        if (activity is { IsAllDataRequested: true })
        {
            activity.SetTag(TelemetryAttributes.ToolName, tool);
            activity.SetTag(TelemetryAttributes.Server, server);
            activity.SetTag(TelemetryAttributes.DownstreamTool, downstreamTool);
        }

        return new ToolCallSpan(this, activity, server is null ? OtherTool : tool, server);
    }

    /// <summary>Records the metrics for a finished call. Called by <see cref="ToolCallSpan"/>.</summary>
    internal void Record(
        string metricTool,
        string? server,
        Decision? decision,
        string? errorType,
        TimeSpan duration)
    {
        var common = new TagList { { TelemetryAttributes.ToolName, metricTool } };
        AddIfPresent(ref common, TelemetryAttributes.Server, server);

        var outcome = common;
        AddIfPresent(ref outcome, TelemetryAttributes.Decision, decision is null ? null : Describe(decision.Verdict));
        AddIfPresent(ref outcome, TelemetryAttributes.ErrorType, errorType);

        _calls.Add(1, outcome);
        _duration.Record(duration.TotalSeconds, outcome);

        if (decision is null)
        {
            return;
        }

        if (decision.IsBlocked)
        {
            var denial = common;
            denial.Add(TelemetryAttributes.DecisionSource, Describe(decision.Source));
            AddIfPresent(ref denial, TelemetryAttributes.Rule, decision.RuleName);
            _denials.Add(1, denial);
        }

        if (decision.ApprovalResult is { } approval)
        {
            var asked = common;
            AddIfPresent(ref asked, TelemetryAttributes.Rule, decision.RuleName);
            asked.Add(TelemetryAttributes.ApprovalOutcome, Describe(approval));
            _approvals.Add(1, asked);
        }
    }

    // An absent value is left out rather than sent as null: exporters disagree on
    // what a null tag means, and "server=null" and "no server" would otherwise
    // become two different series for the same thing.
    private static void AddIfPresent(ref TagList tags, string key, string? value)
    {
        if (value is not null)
        {
            tags.Add(key, value);
        }
    }

    /// <summary>The audit log's spelling of a verdict.</summary>
    public static string Describe(Verdict verdict) => verdict switch
    {
        Verdict.Allow => "allow",
        Verdict.Deny => "deny",
        _ => "require_approval",
    };

    /// <summary>Which guardrail decided, in snake_case.</summary>
    public static string Describe(DecisionSource source) => source switch
    {
        DecisionSource.Budget => "budget",
        DecisionSource.Approval => "approval",
        _ => "policy",
    };

    /// <summary>The audit log's spelling of an approval outcome.</summary>
    public static string Describe(ApprovalOutcome outcome) => outcome switch
    {
        ApprovalOutcome.Approved => "approved",
        ApprovalOutcome.Declined => "declined",
        ApprovalOutcome.TimedOut => "timed_out",
        ApprovalOutcome.Unavailable => "unavailable",
        _ => "failed",
    };

    /// <inheritdoc />
    public void Dispose()
    {
        ActivitySource.Dispose();
        Meter.Dispose();
    }
}

/// <summary>
/// One tool call's span, open from <see cref="ToolCallTelemetry.Start"/> until disposed.
/// </summary>
/// <remarks>
/// Disposing ends the span; <see cref="Complete"/> fills it in and records the
/// metrics. They are separate so the caller can complete inside a <c>finally</c>
/// with everything it learned, while <c>using</c> guarantees the span ends even
/// if completing never happens.
/// </remarks>
public sealed class ToolCallSpan : IDisposable
{
    private readonly ToolCallTelemetry _telemetry;
    private readonly string _metricTool;
    private readonly string? _server;

    internal ToolCallSpan(
        ToolCallTelemetry telemetry,
        Activity? activity,
        string metricTool,
        string? server)
    {
        _telemetry = telemetry;
        Activity = activity;
        _metricTool = metricTool;
        _server = server;
    }

    /// <summary>The underlying span, or null when nothing is listening.</summary>
    public Activity? Activity { get; }

    /// <summary>Records how the call ended.</summary>
    /// <param name="decision">Final guardrail decision, or null if none was reached.</param>
    /// <param name="duration">How long the call took, as the audit log measured it.</param>
    /// <param name="resultIsError">Whether the result sent back had isError set.</param>
    /// <param name="exception">What the call threw, if it threw.</param>
    /// <remarks>
    /// A refusal is NOT an error here, even though the model receives it as an
    /// isError result. A denial is the guardrail working; painting it red would
    /// turn every error-rate panel into a denial-rate panel and bury the calls
    /// that actually broke. Denials are visible through the decision attribute
    /// and the denials counter instead.
    /// </remarks>
    public void Complete(
        Decision? decision,
        TimeSpan duration,
        bool resultIsError,
        Exception? exception = null)
    {
        var errorType = exception is not null
            ? exception.GetType().FullName
            : resultIsError && decision is not { IsBlocked: true } ? ToolCallTelemetry.ToolError : null;

        _telemetry.Record(_metricTool, _server, decision, errorType, duration);

        if (Activity is not { IsAllDataRequested: true })
        {
            return;
        }

        var activity = Activity;

        if (decision is not null)
        {
            activity.SetTag(TelemetryAttributes.Decision, ToolCallTelemetry.Describe(decision.Verdict));
            activity.SetTag(TelemetryAttributes.DecisionSource, ToolCallTelemetry.Describe(decision.Source));
            activity.SetTag(TelemetryAttributes.Rule, decision.RuleName);
            activity.SetTag(TelemetryAttributes.BudgetCost, decision.Cost);

            if (decision.ApprovalResult is { } approval)
            {
                activity.SetTag(TelemetryAttributes.ApprovalOutcome, ToolCallTelemetry.Describe(approval));
            }
        }

        if (errorType is not null)
        {
            // No description: the only text available is an exception message,
            // which can quote arguments. The type is in error.type.
            activity.SetTag(TelemetryAttributes.ErrorType, errorType);
            activity.SetStatus(ActivityStatusCode.Error);
        }
    }

    /// <summary>Ends the span.</summary>
    public void Dispose() => Activity?.Dispose();
}

/// <summary>Attribute names used on guardrails spans and metrics.</summary>
/// <remarks>
/// Public so dashboards, tests and anyone writing a collector processor can
/// refer to the same constants instead of retyping strings.
/// </remarks>
public static class TelemetryAttributes
{
    /// <summary>Semconv: the client-visible tool name.</summary>
    public const string ToolName = "gen_ai.tool.name";

    /// <summary>Semconv: why the operation failed, when it did.</summary>
    public const string ErrorType = "error.type";

    /// <summary>Downstream server that owns the tool.</summary>
    public const string Server = "mcp_guardrails.server";

    /// <summary>The tool's name on the downstream server.</summary>
    public const string DownstreamTool = "mcp_guardrails.downstream_tool";

    /// <summary>allow, deny or require_approval - same values as the audit log.</summary>
    public const string Decision = "mcp_guardrails.decision";

    /// <summary>Which guardrail decided: policy, budget or approval.</summary>
    public const string DecisionSource = "mcp_guardrails.decision.source";

    /// <summary>The rule (or budget limit, e.g. session.max_cost) that decided.</summary>
    public const string Rule = "mcp_guardrails.rule";

    /// <summary>What the call costs against the session budget.</summary>
    public const string BudgetCost = "mcp_guardrails.budget.cost";

    /// <summary>What the human said: approved, declined, timed_out, unavailable, failed.</summary>
    public const string ApprovalOutcome = "mcp_guardrails.approval.outcome";
}
