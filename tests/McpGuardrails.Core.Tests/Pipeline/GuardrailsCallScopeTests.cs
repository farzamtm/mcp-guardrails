using McpGuardrails.Core.Pipeline;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Scanners;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Tests.Pipeline;

/// <summary>
/// Tests for the per-call scope that carries a policy decision from an inner
/// filter back up to the outer audit filter.
/// </summary>
public sealed class GuardrailsCallScopeTests
{
    private static Decision SomeDecision(string rule = "r") =>
        new(Verdict.Deny, "because", rule);

    private static ScanOutcome SomeScan(params string[] heuristics) => new(
        new CallToolResult(),
        new InjectionReport(heuristics),
        ScanEffect.Annotated);

    [Fact]
    public void NoScope_MeansNoCurrent()
    {
        Assert.Null(GuardrailsCallScope.Current);
    }

    [Fact]
    public void Begin_PublishesTheScope_AndDisposeClearsIt()
    {
        using (var scope = GuardrailsCallScope.Begin())
        {
            Assert.Same(scope, GuardrailsCallScope.Current);
        }

        Assert.Null(GuardrailsCallScope.Current);
    }

    [Fact]
    public void RecordDecision_IsVisibleOnTheScope()
    {
        using var scope = GuardrailsCallScope.Begin();

        GuardrailsCallScope.RecordDecision(SomeDecision("deny-writes"));

        Assert.Equal("deny-writes", scope.Decision?.RuleName);
    }

    [Fact]
    public void RecordDecision_WithoutAScope_IsANoOp()
    {
        // The policy filter must remain usable on its own - in tests, or if audit
        // is ever disabled - rather than throwing.
        GuardrailsCallScope.RecordDecision(SomeDecision());

        Assert.Null(GuardrailsCallScope.Current);
    }

    [Fact]
    public void RecordDecision_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => GuardrailsCallScope.RecordDecision(null!));
    }

    [Fact]
    public void DecisionIsNullUntilOneIsRecorded()
    {
        using var scope = GuardrailsCallScope.Begin();

        Assert.Null(scope.Decision);
    }

    // --------------------------------------------------------- result scanning

    [Fact]
    public void RecordScan_IsVisibleOnTheScope()
    {
        using var scope = GuardrailsCallScope.Begin();

        GuardrailsCallScope.RecordScan(SomeScan(InjectionScanner.RoleHijack));

        Assert.Equal([InjectionScanner.RoleHijack], scope.Scan?.Heuristics);
    }

    [Fact]
    public void RecordScan_WithoutAScope_IsANoOp()
    {
        GuardrailsCallScope.RecordScan(SomeScan());

        Assert.Null(GuardrailsCallScope.Current);
    }

    [Fact]
    public void RecordScan_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => GuardrailsCallScope.RecordScan(null!));
    }

    // -------------------------------------------------------- secret redaction

    [Fact]
    public void RecordRedaction_IsVisibleOnTheScope()
    {
        using var scope = GuardrailsCallScope.Begin();
        var outcome = new RedactionOutcome(
            new CallToolResult(),
            new SecretReport([SecretScanner.Jwt], 1),
            RedactionEffect.Redacted);

        GuardrailsCallScope.RecordRedaction(outcome);

        Assert.Same(outcome, scope.Redaction);
    }

    [Fact]
    public void RecordRedaction_WithoutAScope_IsANoOp()
    {
        GuardrailsCallScope.RecordRedaction(
            new RedactionOutcome(new CallToolResult(), SecretReport.Clean, RedactionEffect.None));

        Assert.Null(GuardrailsCallScope.Current);
    }

    [Fact]
    public void RecordRedaction_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => GuardrailsCallScope.RecordRedaction(null!));
    }

    [Fact]
    public void ScanIsNullOnACallThatNeverReturnedAResult()
    {
        // The distinction the audit log depends on: no scanner field means
        // nothing came back to scan, not that what came back was clean.
        using var scope = GuardrailsCallScope.Begin();

        Assert.Null(scope.Scan);
    }

    /// <summary>
    /// The reason this class exists at all.
    /// </summary>
    /// <remarks>
    /// AsyncLocal values flow DOWN into nested async calls but never back UP. If
    /// the inner filter reassigned the AsyncLocal, the outer filter would still
    /// see null. Publishing a mutable holder and mutating its contents is what
    /// makes the value visible to the outer scope - this test pins that
    /// behaviour, because it is the exact bug the design avoids.
    /// </remarks>
    [Fact]
    public async Task DecisionRecordedInNestedAsyncCall_IsVisibleToTheOuterScope()
    {
        using var outer = GuardrailsCallScope.Begin();

        await InnerFilterAsync();

        Assert.Equal("set-from-inner", outer.Decision?.RuleName);

        static async Task InnerFilterAsync()
        {
            await Task.Yield(); // force a real async boundary
            GuardrailsCallScope.RecordDecision(SomeDecision("set-from-inner"));
        }
    }

    [Fact]
    public async Task ConcurrentCalls_DoNotSeeEachOthersDecisions()
    {
        // Two tool calls in flight must not cross-contaminate.
        var first = RunCallAsync("call-one");
        var second = RunCallAsync("call-two");

        var results = await Task.WhenAll(first, second);

        Assert.Equal("call-one", results[0]);
        Assert.Equal("call-two", results[1]);

        static async Task<string?> RunCallAsync(string ruleName)
        {
            using var scope = GuardrailsCallScope.Begin();
            await Task.Yield();
            GuardrailsCallScope.RecordDecision(SomeDecision(ruleName));
            await Task.Delay(10);
            return scope.Decision?.RuleName;
        }
    }

    [Fact]
    public void LastRecordedDecisionWins()
    {
        using var scope = GuardrailsCallScope.Begin();

        GuardrailsCallScope.RecordDecision(SomeDecision("first"));
        GuardrailsCallScope.RecordDecision(SomeDecision("second"));

        Assert.Equal("second", scope.Decision?.RuleName);
    }
}
