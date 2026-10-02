using System.Diagnostics;
using System.Diagnostics.Metrics;
using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Audit;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Audit;

/// <summary>
/// Tests for the span and metrics emitted per tool call.
/// </summary>
/// <remarks>
/// The listeners below are the BCL's own subscription APIs - the same hooks the
/// OpenTelemetry SDK uses - so these tests see exactly what an exporter would,
/// without Core or the tests depending on the SDK. Each test owns its own
/// ToolCallTelemetry, and the listeners match on the instance rather than the
/// name, so tests running in parallel cannot see each other's measurements.
/// </remarks>
public sealed class ToolCallTelemetryTests : IDisposable
{
    private readonly ToolCallTelemetry _telemetry = new();
    private readonly List<Activity> _spans = [];
    private readonly List<Measurement> _measurements = [];
    private readonly ActivityListener _activityListener;
    private readonly MeterListener _meterListener = new();

    private ActivitySamplingResult _sampling = ActivitySamplingResult.AllDataAndRecorded;

    private sealed record Measurement(string Instrument, double Value, Dictionary<string, object?> Tags);

    public ToolCallTelemetryTests()
    {
        _activityListener = new ActivityListener
        {
            ShouldListenTo = source => ReferenceEquals(source, _telemetry.ActivitySource),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => _sampling,
            ActivityStopped = _spans.Add,
        };

        _meterListener.InstrumentPublished = (instrument, listener) =>
        {
            if (ReferenceEquals(instrument.Meter, _telemetry.Meter))
            {
                listener.EnableMeasurementEvents(instrument);
            }
        };
        _meterListener.SetMeasurementEventCallback<long>(
            (instrument, value, tags, _) => Capture(instrument, value, tags));
        _meterListener.SetMeasurementEventCallback<double>(
            (instrument, value, tags, _) => Capture(instrument, value, tags));
    }

    private void Listen()
    {
        ActivitySource.AddActivityListener(_activityListener);
        _meterListener.Start();
    }

    private void Capture(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        var copy = new Dictionary<string, object?>();
        foreach (var tag in tags)
        {
            copy[tag.Key] = tag.Value;
        }

        _measurements.Add(new Measurement(instrument.Name, value, copy));
    }

    private IReadOnlyList<Measurement> Of(string instrument) =>
        [.. _measurements.Where(m => m.Instrument == instrument)];

    public void Dispose()
    {
        _activityListener.Dispose();
        _meterListener.Dispose();
        _telemetry.Dispose();
    }

    private void Run(
        Decision? decision,
        bool resultIsError = false,
        Exception? exception = null,
        string tool = "fs__write_file",
        string? server = "fs",
        string? downstreamTool = "write_file")
    {
        using var span = _telemetry.Start(tool, server, downstreamTool);
        span.Complete(decision, TimeSpan.FromMilliseconds(250), resultIsError, exception);
    }

    [Fact]
    public void WithoutListeners_NoSpanIsCreated_AndCompletingIsHarmless()
    {
        using var span = _telemetry.Start("fs__write_file", "fs", "write_file");

        span.Complete(Decision.DefaultAllow, TimeSpan.FromSeconds(1), resultIsError: false);

        Assert.Null(span.Activity);
    }

    [Fact]
    public void AllowedCall_ProducesAnInternalSpanWithTheDecision()
    {
        Listen();

        Run(new Decision(Verdict.Allow, "fine", "allow-writes") { Cost = 2 });

        var span = Assert.Single(_spans);
        Assert.Equal("guardrails tools/call fs__write_file", span.DisplayName);
        Assert.Equal(ActivityKind.Internal, span.Kind);
        Assert.Equal(ActivityStatusCode.Unset, span.Status);
        Assert.Equal("fs__write_file", span.GetTagItem("gen_ai.tool.name"));
        Assert.Equal("fs", span.GetTagItem("mcp_guardrails.server"));
        Assert.Equal("write_file", span.GetTagItem("mcp_guardrails.downstream_tool"));
        Assert.Equal("allow", span.GetTagItem("mcp_guardrails.decision"));
        Assert.Equal("policy", span.GetTagItem("mcp_guardrails.decision.source"));
        Assert.Equal("allow-writes", span.GetTagItem("mcp_guardrails.rule"));
        Assert.Equal(2L, span.GetTagItem("mcp_guardrails.budget.cost"));
        Assert.Null(span.GetTagItem("error.type"));
        Assert.Null(span.GetTagItem("mcp_guardrails.approval.outcome"));
    }

    [Fact]
    public void AllowedCall_CountsTheCall_AndRecordsLatencyInSeconds()
    {
        Listen();

        Run(Decision.DefaultAllow);

        var call = Assert.Single(Of("mcp_guardrails.tool_calls"));
        Assert.Equal(1, call.Value);
        Assert.Equal("fs__write_file", call.Tags["gen_ai.tool.name"]);
        Assert.Equal("fs", call.Tags["mcp_guardrails.server"]);
        Assert.Equal("allow", call.Tags["mcp_guardrails.decision"]);
        Assert.False(call.Tags.ContainsKey("error.type"));

        var latency = Assert.Single(Of("mcp_guardrails.tool_call.duration"));
        Assert.Equal(0.25, latency.Value, precision: 6);

        Assert.Empty(Of("mcp_guardrails.denials"));
        Assert.Empty(Of("mcp_guardrails.approvals"));
    }

    [Fact]
    public void LatencyHistogram_AdvisesTheMcpSemconvBuckets()
    {
        var histogram = Assert.IsType<Histogram<double>>(
            CaptureInstrument("mcp_guardrails.tool_call.duration"));

        Assert.Equal("s", histogram.Unit);
        Assert.Equal(
            [0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 30, 60, 120, 300],
            histogram.Advice?.HistogramBucketBoundaries);
    }

    private Instrument? CaptureInstrument(string name)
    {
        Instrument? found = null;
        using var listener = new MeterListener
        {
            InstrumentPublished = (instrument, _) =>
            {
                if (ReferenceEquals(instrument.Meter, _telemetry.Meter) && instrument.Name == name)
                {
                    found = instrument;
                }
            },
        };
        listener.Start();
        return found;
    }

    /// <summary>
    /// A client can send any tool name it likes. Using it as a metric tag would
    /// let a misbehaving agent create a time series per call.
    /// </summary>
    [Fact]
    public void UnresolvedTool_StaysOutOfTheSpanNameAndTheMetricTags()
    {
        Listen();

        Run(decision: null, resultIsError: true, tool: "random-1234", server: null, downstreamTool: null);

        var span = Assert.Single(_spans);
        Assert.Equal("guardrails tools/call", span.DisplayName);
        Assert.Equal("random-1234", span.GetTagItem("gen_ai.tool.name"));
        Assert.Null(span.GetTagItem("mcp_guardrails.server"));
        Assert.Null(span.GetTagItem("mcp_guardrails.decision"));

        var call = Assert.Single(Of("mcp_guardrails.tool_calls"));
        Assert.Equal(ToolCallTelemetry.OtherTool, call.Tags["gen_ai.tool.name"]);
        Assert.False(call.Tags.ContainsKey("mcp_guardrails.server"));
        Assert.False(call.Tags.ContainsKey("mcp_guardrails.decision"));
        Assert.Equal("tool_error", call.Tags["error.type"]);

        Assert.Empty(Of("mcp_guardrails.denials"));
        Assert.Empty(Of("mcp_guardrails.approvals"));
    }

    /// <summary>
    /// A refusal reaches the model as an isError result, but it is the guardrail
    /// working, not a failure. Marking it red would drown real errors.
    /// </summary>
    [Fact]
    public void PolicyDenial_IsCountedAsADenial_NotAsAnError()
    {
        Listen();

        Run(new Decision(Verdict.Deny, "no", "deny-writes"), resultIsError: true);

        var span = Assert.Single(_spans);
        Assert.Equal(ActivityStatusCode.Unset, span.Status);
        Assert.Null(span.GetTagItem("error.type"));
        Assert.Equal("deny", span.GetTagItem("mcp_guardrails.decision"));

        var denial = Assert.Single(Of("mcp_guardrails.denials"));
        Assert.Equal("policy", denial.Tags["mcp_guardrails.decision.source"]);
        Assert.Equal("deny-writes", denial.Tags["mcp_guardrails.rule"]);
        Assert.Equal("fs__write_file", denial.Tags["gen_ai.tool.name"]);
        Assert.False(denial.Tags.ContainsKey("mcp_guardrails.decision"));

        var call = Assert.Single(Of("mcp_guardrails.tool_calls"));
        Assert.False(call.Tags.ContainsKey("error.type"));
    }

    [Fact]
    public void DenialWithoutARule_OmitsTheRuleTag()
    {
        Listen();

        Run(new Decision(Verdict.Deny, "no"), resultIsError: true);

        var denial = Assert.Single(Of("mcp_guardrails.denials"));
        Assert.False(denial.Tags.ContainsKey("mcp_guardrails.rule"));
        Assert.Null(Assert.Single(_spans).GetTagItem("mcp_guardrails.rule"));
    }

    [Fact]
    public void BudgetDenial_NamesTheLimitThatRanOut()
    {
        Listen();

        Run(
            new Decision(Verdict.Deny, "spent", "session.max_cost")
            {
                Source = DecisionSource.Budget,
                Cost = 5,
            },
            resultIsError: true);

        var span = Assert.Single(_spans);
        Assert.Equal("budget", span.GetTagItem("mcp_guardrails.decision.source"));
        Assert.Equal("session.max_cost", span.GetTagItem("mcp_guardrails.rule"));
        Assert.Equal(5L, span.GetTagItem("mcp_guardrails.budget.cost"));

        var denial = Assert.Single(Of("mcp_guardrails.denials"));
        Assert.Equal("budget", denial.Tags["mcp_guardrails.decision.source"]);
        Assert.Equal("session.max_cost", denial.Tags["mcp_guardrails.rule"]);
    }

    [Theory]
    [InlineData(ApprovalOutcome.Approved, Verdict.Allow, "approved")]
    [InlineData(ApprovalOutcome.Declined, Verdict.Deny, "declined")]
    [InlineData(ApprovalOutcome.TimedOut, Verdict.Deny, "timed_out")]
    [InlineData(ApprovalOutcome.Unavailable, Verdict.Deny, "unavailable")]
    [InlineData(ApprovalOutcome.Failed, Verdict.Deny, "failed")]
    public void ApprovalOutcome_IsRecordedOnTheSpanAndCounted(
        ApprovalOutcome outcome, Verdict verdict, string expected)
    {
        Listen();

        Run(new Decision(verdict, "asked", "approve-writes")
        {
            Source = DecisionSource.Approval,
            ApprovalResult = outcome,
        });

        Assert.Equal(expected, Assert.Single(_spans).GetTagItem("mcp_guardrails.approval.outcome"));

        var asked = Assert.Single(Of("mcp_guardrails.approvals"));
        Assert.Equal(expected, asked.Tags["mcp_guardrails.approval.outcome"]);
        Assert.Equal("approve-writes", asked.Tags["mcp_guardrails.rule"]);

        // Only a "no" from the approval step is a denial.
        Assert.Equal(verdict == Verdict.Deny ? 1 : 0, Of("mcp_guardrails.denials").Count);
    }

    [Fact]
    public void ApprovalWithoutARule_OmitsTheRuleTag()
    {
        Listen();

        Run(new Decision(Verdict.Allow, "asked") { ApprovalResult = ApprovalOutcome.Approved });

        var asked = Assert.Single(Of("mcp_guardrails.approvals"));
        Assert.False(asked.Tags.ContainsKey("mcp_guardrails.rule"));
    }

    [Fact]
    public void ForwardedCallThatFails_IsAToolError()
    {
        Listen();

        Run(Decision.DefaultAllow, resultIsError: true);

        var span = Assert.Single(_spans);
        Assert.Equal(ActivityStatusCode.Error, span.Status);
        Assert.Equal("tool_error", span.GetTagItem("error.type"));
        Assert.Equal("tool_error", Assert.Single(Of("mcp_guardrails.tool_calls")).Tags["error.type"]);
    }

    /// <summary>
    /// Exception messages can quote the arguments that caused them, and a trace
    /// backend has no redaction step, so only the type leaves the process.
    /// </summary>
    [Fact]
    public void Exception_RecordsItsTypeButNeverItsMessage()
    {
        Listen();

        Run(Decision.DefaultAllow, exception: new IOException("secret-token-abc123"));

        var span = Assert.Single(_spans);
        Assert.Equal(ActivityStatusCode.Error, span.Status);
        Assert.Null(span.StatusDescription);
        Assert.Equal("System.IO.IOException", span.GetTagItem("error.type"));
        Assert.Empty(span.Events);
        Assert.DoesNotContain(
            span.TagObjects,
            tag => tag.Value?.ToString()?.Contains("secret-token", StringComparison.Ordinal) is true);

        var call = Assert.Single(Of("mcp_guardrails.tool_calls"));
        Assert.Equal("System.IO.IOException", call.Tags["error.type"]);
    }

    /// <summary>
    /// A sampler that keeps only the trace context still gets a span to parent
    /// downstream calls on, but attributes are not worth computing for it.
    /// </summary>
    [Fact]
    public void PropagationOnlySampling_SkipsAttributes_ButStillRecordsMetrics()
    {
        _sampling = ActivitySamplingResult.PropagationData;
        Listen();

        Run(new Decision(Verdict.Deny, "no", "deny-writes"), resultIsError: true);

        var span = Assert.Single(_spans);
        Assert.False(span.IsAllDataRequested);
        Assert.Empty(span.TagObjects);
        Assert.Single(Of("mcp_guardrails.denials"));
    }

    [Fact]
    public void Span_IsCurrentWhileTheCallRuns_SoDownstreamSpansNestUnderIt()
    {
        Listen();

        using var span = _telemetry.Start("fs__write_file", "fs", "write_file");

        Assert.NotNull(span.Activity);
        Assert.Same(span.Activity, Activity.Current);
    }

    [Fact]
    public void Start_RejectsANullToolName()
    {
        Assert.Throws<ArgumentNullException>(() => _telemetry.Start(null!, "fs", "write_file"));
    }

    [Theory]
    [InlineData(Verdict.Allow, "allow")]
    [InlineData(Verdict.Deny, "deny")]
    [InlineData(Verdict.RequireApproval, "require_approval")]
    public void Describe_Verdict_UsesTheAuditLogSpelling(Verdict verdict, string expected)
    {
        Assert.Equal(expected, ToolCallTelemetry.Describe(verdict));
    }

    [Theory]
    [InlineData(DecisionSource.Policy, "policy")]
    [InlineData(DecisionSource.Budget, "budget")]
    [InlineData(DecisionSource.Approval, "approval")]
    public void Describe_Source_IsSnakeCase(DecisionSource source, string expected)
    {
        Assert.Equal(expected, ToolCallTelemetry.Describe(source));
    }

    [Fact]
    public void SourceAndMeter_ShareTheNameTheExporterSubscribesTo()
    {
        Assert.Equal("McpGuardrails", _telemetry.ActivitySource.Name);
        Assert.Equal("McpGuardrails", _telemetry.Meter.Name);
    }
}
