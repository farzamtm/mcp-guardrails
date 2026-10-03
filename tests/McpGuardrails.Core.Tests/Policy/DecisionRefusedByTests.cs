using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Policy;

/// <summary>
/// Tests for the one way a later gate overturns a decision into a refusal.
/// </summary>
public sealed class DecisionRefusedByTests
{
    private static readonly ApprovalSettings _settings = new() { TimeoutSeconds = 30 };

    private static Decision Approved(IReadOnlyList<string>? trail = null) =>
        new(Verdict.Allow, "Approved by a human for rule 'r'.", "r", trail)
        {
            Cost = 7,
            Approval = _settings,
            ApprovalResult = ApprovalOutcome.Approved,
        };

    [Fact]
    public void TheRefusal_ReplacesVerdictReasonRuleAndSource()
    {
        var refused = Approved().RefusedBy(DecisionSource.Budget, "session.max_calls", "spent", "entry");

        Assert.Equal(Verdict.Deny, refused.Verdict);
        Assert.Equal("spent", refused.Reason);
        Assert.Equal("session.max_calls", refused.RuleName);
        Assert.Equal(DecisionSource.Budget, refused.Source);
    }

    [Fact]
    public void WhatEarlierGatesRecorded_Survives()
    {
        // The drift this helper exists to stop: a hand-built refusal dropped the
        // human's answer, so the audit log lost the approval.
        var refused = Approved().RefusedBy(DecisionSource.Budget, "session.max_calls", "spent", "entry");

        Assert.Equal(7, refused.Cost);
        Assert.Same(_settings, refused.Approval);
        Assert.Equal(ApprovalOutcome.Approved, refused.ApprovalResult);
    }

    [Fact]
    public void UnderExplain_TheEntryIsAppendedToTheTrail()
    {
        var refused = Approved(["earlier"]).RefusedBy(DecisionSource.Scanner, "s", "found", "entry");

        Assert.Equal(["earlier", "entry"], refused.Trail);
    }

    [Fact]
    public void WithoutExplain_NoTrailIsStarted()
    {
        var refused = Approved().RefusedBy(DecisionSource.Scanner, "s", "found", "entry");

        Assert.Null(refused.Trail);
    }
}
