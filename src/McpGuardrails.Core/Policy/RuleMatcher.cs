namespace McpGuardrails.Core.Policy;

/// <summary>Whether a rule applied, did not apply, or could not be decided.</summary>
internal enum MatchState
{
    /// <summary>At least one condition did not hold.</summary>
    NotMatched,

    /// <summary>Every condition held.</summary>
    Matched,

    /// <summary>
    /// A condition could not be evaluated, so whether the rule applies is
    /// unknown. Distinct from <see cref="NotMatched"/> on purpose: collapsing
    /// the two would let an unanswerable condition disarm the rule.
    /// </summary>
    Indeterminate,
}

/// <summary>
/// Whether a rule applied and, when it did not, which condition decided that -
/// so <c>--explain</c> can name it.
/// </summary>
/// <param name="State">Matched, not matched, or undecidable.</param>
/// <param name="Condition">The deciding condition: tool, server, principal, groups, annotations or argument.</param>
/// <param name="Detail">
/// The argument path, when the deciding condition was a predicate. A reference to
/// the rule's own string, never a newly built one.
/// </param>
/// <remarks>
/// A <c>readonly record struct</c>, so reporting the reason costs no allocation.
/// This runs for every rule of every tool call, and the trail is formatted only
/// when the user asked for it.
/// </remarks>
internal readonly record struct MatchOutcome(MatchState State, string? Condition, string? Detail)
{
    internal static MatchOutcome Matched { get; } = new(MatchState.Matched, null, null);

    internal static MatchOutcome Failed(string condition, string? detail = null) =>
        new(MatchState.NotMatched, condition, detail);

    internal static MatchOutcome Undecidable(string condition, string? detail) =>
        new(MatchState.Indeterminate, condition, detail);

    internal bool IsMatch => State is MatchState.Matched;

    internal bool IsIndeterminate => State is MatchState.Indeterminate;
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
    internal const string ServerCondition = "server";
    internal const string PrincipalCondition = "principal";
    internal const string GroupsCondition = "groups";
    internal const string AnnotationsCondition = "annotations";
    internal const string ArgumentCondition = "argument";

    internal static MatchOutcome Match(PolicyMatch match, ToolCallFacts facts)
    {
        if (match.Tool is { } pattern && !GlobMatcher.IsMatch(pattern, facts.ToolName))
        {
            return MatchOutcome.Failed(ToolCondition);
        }

        // An unresolved tool has no server, and "no server" matches no pattern:
        // a rule scoped to one server must not reach calls nobody serves.
        if (match.Server is { } serverPattern &&
            (facts.Server is not { } server || !GlobMatcher.IsMatch(serverPattern, server)))
        {
            return MatchOutcome.Failed(ServerCondition);
        }

        // No caller - stdio, or HTTP without access.oauth - matches no identity
        // condition, for the same reason no server matches no server pattern.
        // Case-insensitive, unlike tool names: principals are often email
        // addresses or UPNs, which identity providers emit in whatever case the
        // account was created with, and a deny rule for "*@contractor.example"
        // that missed "bob@Contractor.Example" would fail open.
        if (match.Principal is { } principalPattern &&
            (facts.Principal is not { } principal || !GlobMatcher.IsMatch(principalPattern, principal, ignoreCase: true)))
        {
            return MatchOutcome.Failed(PrincipalCondition);
        }

        if (match.Groups is { } groups &&
            !groups.Any(group => facts.EffectiveGroups.Contains(group, StringComparer.Ordinal)))
        {
            return MatchOutcome.Failed(GroupsCondition);
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
                switch (predicate.Evaluate(facts.Arguments))
                {
                    case PredicateResult.Satisfied:
                        continue;

                    // Propagated rather than folded into a non-match: only the
                    // evaluator knows that the safe reading of "unknown" is to
                    // refuse the call.
                    case PredicateResult.Indeterminate:
                        return MatchOutcome.Undecidable(ArgumentCondition, predicate.Path);

                    default:
                        return MatchOutcome.Failed(ArgumentCondition, predicate.Path);
                }
            }
        }

        return MatchOutcome.Matched;
    }
}
