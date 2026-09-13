using System.Text.Json.Serialization;

namespace McpGuardrails.Core.Policy;

/// <summary>
/// A parsed policy file.
/// </summary>
/// <remarks>
/// Rules are evaluated in order and the first match wins. That is a deliberate
/// choice over "most specific wins": first-match-wins is predictable by reading
/// top to bottom, whereas specificity scoring makes people guess. Firewall rules
/// and routing tables work the same way for the same reason.
/// </remarks>
public sealed record PolicyDocument
{
    /// <summary>Rules in evaluation order.</summary>
    [JsonPropertyName("rules")]
    public IReadOnlyList<PolicyRule> Rules { get; init; } = [];

    /// <summary>An empty policy: everything allowed, nothing configured.</summary>
    public static PolicyDocument Empty { get; } = new();
}

/// <summary>
/// One rule: what to match, and what to do about it.
/// </summary>
public sealed record PolicyRule
{
    /// <summary>Human-readable name, used in denial messages and the trail.</summary>
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    /// <summary>
    /// Conditions that must all hold for this rule to apply, or null when the
    /// rule specifies none (a catch-all).
    /// </summary>
    /// <remarks>
    /// Nullable rather than defaulted with a property initializer. Initializers
    /// are NOT applied by System.Text.Json's source-generated deserializer, so a
    /// policy file omitting `match` produced a null here and crashed validation.
    /// Modelling "absent" explicitly is both honest and robust; read it through
    /// <see cref="EffectiveMatch"/>.
    /// </remarks>
    [JsonPropertyName("match")]
    public PolicyMatch? Match { get; init; }

    /// <summary>The rule's conditions, or a match-everything default.</summary>
    [JsonIgnore]
    public PolicyMatch EffectiveMatch => Match ?? PolicyMatch.Any;

    /// <summary>
    /// What to do when the rule applies, or null when the file does not say.
    /// </summary>
    /// <remarks>
    /// Nullable for the same reason as <see cref="Match"/>, and here the bug was
    /// worse: an omitted decision silently became Verdict.Allow, because Allow is
    /// the zero value of the enum. A rule written to block something would have
    /// permitted it instead. Read it through <see cref="EffectiveDecision"/>,
    /// which fails closed.
    /// </remarks>
    [JsonPropertyName("decision")]
    public Verdict? Decision { get; init; }

    /// <summary>The decision, defaulting to Deny when unspecified.</summary>
    /// <remarks>Absent means deny: a security policy must fail closed.</remarks>
    [JsonIgnore]
    public Verdict EffectiveDecision => Decision ?? Verdict.Deny;

    /// <summary>
    /// Explanation handed to the model when this rule blocks a call.
    /// </summary>
    /// <remarks>
    /// Optional, but omitting it wastes the rule's best feature. Write it as an
    /// instruction to the agent, not a note to yourself.
    /// </remarks>
    [JsonPropertyName("message")]
    public string? Message { get; init; }

    /// <summary>Validates the rule, throwing with a message naming the problem.</summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Name))
        {
            throw new PolicyException("Every rule needs a non-empty 'name'.");
        }

        if (!Enum.IsDefined(EffectiveDecision))
        {
            throw new PolicyException(
                $"Rule '{Name}' has an unknown decision. " +
                "Use allow, deny or require_approval.");
        }

        EffectiveMatch.Validate(Name);
    }
}

/// <summary>
/// The conditions of a rule. All specified conditions must hold (logical AND).
/// </summary>
/// <remarks>
/// Three kinds of condition, deliberately ordered cheapest-first in
/// <see cref="RuleMatcher"/>: a tool-name glob, the tool's advertised behaviour
/// hints, and predicates over the arguments the model supplied. Most rules never
/// get past the name.
/// </remarks>
public sealed record PolicyMatch
{
    /// <summary>A match with no conditions, which applies to every tool.</summary>
    public static PolicyMatch Any { get; } = new();

    /// <summary>
    /// Tool name to match, as the client sees it (e.g. <c>fs__write_file</c>).
    /// </summary>
    /// <remarks>
    /// A glob: <c>*</c> matches any run of characters and <c>?</c> exactly one,
    /// so <c>fs__*</c> covers a whole server and <c>*__delete_*</c> covers a verb
    /// across every server. A pattern with no wildcard is an exact, ordinal,
    /// case-sensitive match, so existing policy files keep their meaning.
    /// </remarks>
    [JsonPropertyName("tool")]
    public string? Tool { get; init; }

    /// <summary>Behaviour hints the tool must advertise, if any.</summary>
    [JsonPropertyName("annotations")]
    public AnnotationMatch? Annotations { get; init; }

    /// <summary>
    /// Conditions on the call's arguments; all must hold.
    /// </summary>
    /// <remarks>
    /// Named <c>args</c> in the policy file because that is what the thing is
    /// called at the call site, and policy files are read far more often than
    /// this class is.
    /// </remarks>
    [JsonPropertyName("args")]
    public IReadOnlyList<ArgumentPredicate>? Arguments { get; init; }

    /// <summary>True when this match specifies no conditions at all.</summary>
    /// <remarks>
    /// A rule that matches everything is legal and useful (a catch-all deny at
    /// the bottom of the file), but it is worth being able to detect.
    /// </remarks>
    [JsonIgnore]
    public bool IsCatchAll => Tool is null && Annotations is null && Arguments is null;

    internal void Validate(string ruleName)
    {
        if (Tool is not null && string.IsNullOrWhiteSpace(Tool))
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has an empty 'tool'. " +
                "Omit the field entirely to match every tool.");
        }

        Annotations?.Validate(ruleName);

        if (Arguments is null)
        {
            return;
        }

        if (Arguments.Count == 0)
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has an empty 'args' list. " +
                "Omit the field entirely to match regardless of arguments.");
        }

        foreach (var predicate in Arguments)
        {
            predicate.Validate(ruleName);
        }
    }
}

/// <summary>
/// Raised for a malformed policy file.
/// </summary>
/// <remarks>
/// A dedicated exception type so the CLI can print a clean configuration error
/// instead of a stack trace. A bad policy is a user mistake, not a crash.
/// </remarks>
public sealed class PolicyException : Exception
{
    public PolicyException(string message) : base(message)
    {
    }

    public PolicyException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
