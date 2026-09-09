using System.Text.Json;

namespace McpGuardrails.Core.Policy;

/// <summary>
/// The facts about a tool call that rules are matched against.
/// </summary>
/// <param name="ToolName">Client-visible name, e.g. <c>fs__write_file</c>.</param>
/// <param name="Arguments">Arguments supplied by the model, if any.</param>
/// <remarks>
/// Deliberately a plain data snapshot rather than the live MCP request: it keeps
/// the evaluator free of any protocol types, which is what makes it trivially
/// unit-testable. Step 6 adds tool annotations here.
/// </remarks>
public sealed record ToolCallFacts(
    string ToolName,
    IReadOnlyDictionary<string, JsonElement>? Arguments = null);

/// <summary>
/// Decides what to do with a tool call, first matching rule wins.
/// </summary>
/// <remarks>
/// Pure and deterministic: no I/O, no clock, no randomness. Same facts and same
/// policy always give the same decision, which is what makes the audit trail
/// meaningful and the tests exhaustive.
/// </remarks>
public sealed class PolicyEvaluator
{
    private readonly PolicyDocument _policy;

    public PolicyEvaluator(PolicyDocument policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        foreach (var rule in policy.Rules)
        {
            rule.Validate();
        }

        _policy = policy;
    }

    /// <summary>An evaluator with no rules: allows everything.</summary>
    public static PolicyEvaluator Empty { get; } = new(PolicyDocument.Empty);

    /// <summary>
    /// Evaluates one call.
    /// </summary>
    /// <param name="facts">What is being called.</param>
    /// <param name="explain">
    /// When true, record every rule considered in <see cref="Decision.Trail"/>.
    /// Off by default because building the trail costs allocations on a path that
    /// runs for every single tool call.
    /// </param>
    public Decision Evaluate(ToolCallFacts facts, bool explain = false)
    {
        ArgumentNullException.ThrowIfNull(facts);

        // `List<string>?` stays null unless explaining, so the common path does
        // not allocate at all.
        List<string>? trail = explain ? [] : null;

        foreach (var rule in _policy.Rules)
        {
            // EffectiveMatch / EffectiveDecision, never the raw nullable
            // properties: an omitted `decision:` must mean Deny, and reading
            // rule.Decision directly would give null (and previously, silently,
            // Allow - the zero value of the enum).
            if (Matches(rule.EffectiveMatch, facts))
            {
                trail?.Add($"rule '{rule.Name}': MATCHED -> {Describe(rule.EffectiveDecision)}");

                return new Decision(
                    rule.EffectiveDecision,
                    rule.Message ?? DefaultMessage(rule),
                    rule.Name,
                    trail);
            }

            trail?.Add($"rule '{rule.Name}': no match");
        }

        trail?.Add("no rule matched -> default allow");

        return trail is null
            ? Decision.DefaultAllow
            : Decision.DefaultAllow with { Trail = trail };
    }

    private static bool Matches(PolicyMatch match, ToolCallFacts facts)
    {
        // A match with no conditions matches everything. Each condition below is
        // skipped when unspecified, so conditions combine with AND.
        if (match.Tool is not null &&
            !string.Equals(match.Tool, facts.ToolName, StringComparison.Ordinal))
        {
            return false;
        }

        return true;
    }

    /// <remarks>
    /// internal so tests can reach the defensive default arm. Validation rejects
    /// undefined verdicts in the constructor, so that arm is unreachable through
    /// the public API - but the compiler still requires it, and untested code in
    /// a security component is not something to wave through.
    /// </remarks>
    internal static string DefaultMessage(PolicyRule rule) => rule.EffectiveDecision switch
    {
        // `switch` expression with pattern matching. Every arm returns a value,
        // and the compiler warns if the enum gains a member this does not handle
        // - which, with warnings-as-errors, means it cannot be forgotten.
        Verdict.Deny =>
            $"This tool is not permitted by rule '{rule.Name}'. " +
            "Do not retry; choose a different approach.",
        Verdict.RequireApproval =>
            $"Rule '{rule.Name}' requires human approval before this call can proceed.",
        Verdict.Allow =>
            $"Explicitly allowed by rule '{rule.Name}'.",
        _ => $"Rule '{rule.Name}' applied.",
    };

    internal static string Describe(Verdict verdict) => verdict switch
    {
        Verdict.Allow => "allow",
        Verdict.Deny => "deny",
        Verdict.RequireApproval => "require_approval",
        _ => verdict.ToString(),
    };
}
