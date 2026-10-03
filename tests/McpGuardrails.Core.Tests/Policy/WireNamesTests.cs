using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Policy;

/// <summary>
/// Tests for the one spelling of each decision enum in the audit log and telemetry.
/// </summary>
/// <remarks>
/// The GetValues loops are the guard the compiler cannot give: the switches end
/// in a throwing discard arm, so a member added without a spelling compiles and
/// only fails here.
/// </remarks>
public sealed class WireNamesTests
{
    [Theory]
    [InlineData(Verdict.Allow, "allow")]
    [InlineData(Verdict.Deny, "deny")]
    [InlineData(Verdict.RequireApproval, "require_approval")]
    public void Verdict_UsesThePolicyFileSpelling(Verdict verdict, string expected)
    {
        Assert.Equal(expected, verdict.ToWireName());
    }

    [Theory]
    [InlineData(DecisionSource.Policy, "policy")]
    [InlineData(DecisionSource.Budget, "budget")]
    [InlineData(DecisionSource.Approval, "approval")]
    [InlineData(DecisionSource.Scanner, "scanner")]
    public void Source_IsSnakeCase(DecisionSource source, string expected)
    {
        Assert.Equal(expected, source.ToWireName());
    }

    [Theory]
    [InlineData(ApprovalOutcome.Approved, "approved")]
    [InlineData(ApprovalOutcome.Declined, "declined")]
    [InlineData(ApprovalOutcome.TimedOut, "timed_out")]
    [InlineData(ApprovalOutcome.Unavailable, "unavailable")]
    [InlineData(ApprovalOutcome.Failed, "failed")]
    public void ApprovalOutcome_IsSnakeCase(ApprovalOutcome outcome, string expected)
    {
        Assert.Equal(expected, outcome.ToWireName());
    }

    [Fact]
    public void EveryVerdict_HasADistinctSpelling()
    {
        AssertDistinct(Enum.GetValues<Verdict>().Select(WireNames.ToWireName));
    }

    [Fact]
    public void EverySource_HasADistinctSpelling()
    {
        AssertDistinct(Enum.GetValues<DecisionSource>().Select(WireNames.ToWireName));
    }

    [Fact]
    public void EveryApprovalOutcome_HasADistinctSpelling()
    {
        AssertDistinct(Enum.GetValues<ApprovalOutcome>().Select(WireNames.ToWireName));
    }

    [Fact]
    public void AnUndefinedValue_Throws_RatherThanBorrowingAnotherName()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => ((Verdict)99).ToWireName());
        Assert.Throws<ArgumentOutOfRangeException>(() => ((DecisionSource)99).ToWireName());
        Assert.Throws<ArgumentOutOfRangeException>(() => ((ApprovalOutcome)99).ToWireName());
    }

    // Every value maps (no throw) and no two values collide - a copy-pasted arm
    // would log two different events under one word.
    private static void AssertDistinct(IEnumerable<string> names)
    {
        var list = names.ToList();

        Assert.All(list, name => Assert.Matches("^[a-z_]+$", name));
        Assert.Equal(list.Count, list.Distinct(StringComparer.Ordinal).Count());
    }
}
