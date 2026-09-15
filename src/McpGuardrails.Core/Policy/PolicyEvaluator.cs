namespace McpGuardrails.Core.Policy;

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
            var outcome = RuleMatcher.Match(rule.EffectiveMatch, facts);

            if (outcome.IsMatch)
            {
                trail?.Add($"rule '{rule.Name}': MATCHED -> {Describe(rule.EffectiveDecision)}");

                return new Decision(
                    rule.EffectiveDecision,
                    rule.Message ?? DefaultMessage(rule),
                    rule.Name,
                    trail);
            }

            // A rule that could not be evaluated stops the walk and refuses the
            // call. Continuing would treat "we do not know" as "the rule does
            // not apply", which is the same as deleting the rule - and since a
            // condition is only undecidable because of the argument the caller
            // supplied, the caller would be choosing which rules to skip. The
            // verdict is Deny whatever the rule's own decision is: an unchecked
            // guardrail is a reason to stop, not a reason to proceed.
            if (outcome.IsIndeterminate)
            {
                trail?.Add($"rule '{rule.Name}': UNDECIDABLE ({DescribeMiss(outcome)}) -> deny");

                return new Decision(
                    Verdict.Deny,
                    UndecidableMessage(rule, outcome),
                    rule.Name,
                    trail);
            }

            // Naming the condition that failed is what makes --explain worth
            // running: "no match" tells you nothing when a rule has three of them.
            trail?.Add($"rule '{rule.Name}': no match ({DescribeMiss(outcome)})");
        }

        trail?.Add("no rule matched -> default allow");

        return trail is null
            ? Decision.DefaultAllow
            : Decision.DefaultAllow with { Trail = trail };
    }

    private static string DescribeMiss(MatchOutcome outcome) =>
        outcome.Detail is null ? outcome.Condition! : $"{outcome.Condition} {outcome.Detail}";

    /// <remarks>
    /// Written for the model, like every other denial: it says what to change
    /// rather than just that something went wrong, because the one input the
    /// caller controls here is the size of the argument.
    /// </remarks>
    private static string UndecidableMessage(PolicyRule rule, MatchOutcome outcome) =>
        $"Rule '{rule.Name}' could not be evaluated: the {DescribeMiss(outcome)} condition " +
        "exceeded its time budget. The call is refused because a guardrail could not be " +
        "checked. Retry with a substantially smaller argument value.";

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
