using McpGuardrails.Core.Approval;

namespace McpGuardrails.Core.Policy;

/// <summary>
/// The one spelling of each decision enum used outside the process: in the audit
/// log, on spans and metric tags, in the <c>--explain</c> trail and in policy
/// errors.
/// </summary>
/// <remarks>
/// One place, because the copies drifted. The audit log wrote
/// <c>requireapproval</c> where telemetry wrote <c>require_approval</c>, and
/// telemetry reported a scanner refusal as <c>policy</c> because its fallback arm
/// swallowed a member added later. A dashboard and a jq query that disagree about
/// the same call are worse than either alone.
///
/// Every member is named and the last arm throws rather than falling back to a
/// plausible string, so a value cast from an out-of-range integer - or a member
/// added without a spelling - fails loudly instead of being logged under
/// somebody else's name. The compiler cannot catch the second case once a
/// discard arm exists, so WireNamesTests walks Enum.GetValues for every enum
/// here: a new member without a spelling fails the build's test step.
///
/// snake_case throughout, matching the policy file (<c>decision:
/// require_approval</c>), so <c>jq 'select(.decision == "require_approval")'</c>
/// uses the word the operator already typed.
/// </remarks>
public static class WireNames
{
    /// <summary>allow, deny or require_approval.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not a defined verdict.</exception>
    public static string ToWireName(this Verdict verdict) => verdict switch
    {
        Verdict.Allow => "allow",
        Verdict.Deny => "deny",
        Verdict.RequireApproval => "require_approval",
        _ => throw Unknown(nameof(verdict), verdict),
    };

    /// <summary>policy, budget, approval or scanner.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not a defined source.</exception>
    public static string ToWireName(this DecisionSource source) => source switch
    {
        DecisionSource.Policy => "policy",
        DecisionSource.Budget => "budget",
        DecisionSource.Approval => "approval",
        DecisionSource.Scanner => "scanner",
        _ => throw Unknown(nameof(source), source),
    };

    /// <summary>approved, declined, timed_out, unavailable or failed.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not a defined outcome.</exception>
    public static string ToWireName(this ApprovalOutcome outcome) => outcome switch
    {
        ApprovalOutcome.Approved => "approved",
        ApprovalOutcome.Declined => "declined",
        ApprovalOutcome.TimedOut => "timed_out",
        ApprovalOutcome.Unavailable => "unavailable",
        ApprovalOutcome.Failed => "failed",
        _ => throw Unknown(nameof(outcome), outcome),
    };

    private static ArgumentOutOfRangeException Unknown<T>(string name, T value)
        where T : struct, Enum =>
        new(name, value, $"No wire name is defined for {typeof(T).Name} value {value}.");
}
