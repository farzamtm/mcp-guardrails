namespace McpGuardrails.Core.Policy;

/// <summary>
/// Why a rule did not apply, so <c>--explain</c> can say which condition failed.
/// </summary>
/// <param name="IsMatch">True when every condition held.</param>
/// <param name="Condition">The condition that failed: tool, annotations or argument.</param>
/// <param name="Detail">
/// The argument path, when the failing condition was a predicate. A reference to
/// the rule's own string, never a newly built one.
/// </param>
/// <remarks>
/// A <c>readonly record struct</c>, so reporting the reason costs no allocation.
/// This runs for every rule of every tool call, and the trail is formatted only
/// when the user asked for it.
/// </remarks>
internal readonly record struct MatchOutcome(bool IsMatch, string? Condition, string? Detail)
{
    internal static MatchOutcome Matched { get; } = new(true, null, null);

    internal static MatchOutcome Failed(string condition, string? detail = null) =>
        new(false, condition, detail);
}

/// <summary>
/// Decides whether one rule's conditions hold for one tool call.
/// </summary>
/// <remarks>
/// Split out of <see cref="PolicyEvaluator"/> so that "does this rule apply?" and
/// "which rule wins?" are separately testable. The evaluator owns ordering,
/// precedence and the trail; this owns the matching semantics.
///
/// Conditions combine with AND, and an unspecified condition is skipped. A match
/// block with nothing in it therefore matches every call, which is how a
/// catch-all rule at the bottom of a policy file is written.
/// </remarks>
internal static class RuleMatcher
{
    internal const string ToolCondition = "tool";
    internal const string AnnotationsCondition = "annotations";
    internal const string ArgumentCondition = "argument";

    internal static MatchOutcome Match(PolicyMatch match, ToolCallFacts facts)
    {
        if (match.Tool is { } pattern && !GlobMatcher.IsMatch(pattern, facts.ToolName))
        {
            return MatchOutcome.Failed(ToolCondition);
        }

        if (match.Annotations is { } annotations &&
            !annotations.Matches(facts.EffectiveAnnotations))
        {
            return MatchOutcome.Failed(AnnotationsCondition);
        }

        if (match.Arguments is { } predicates)
        {
            foreach (var predicate in predicates)
            {
                if (!predicate.Evaluate(facts.Arguments))
                {
                    return MatchOutcome.Failed(ArgumentCondition, predicate.Path);
                }
            }
        }

        return MatchOutcome.Matched;
    }
}
