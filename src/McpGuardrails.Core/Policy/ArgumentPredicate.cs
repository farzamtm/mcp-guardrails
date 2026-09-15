using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace McpGuardrails.Core.Policy;

/// <summary>
/// The outcome of applying one <see cref="ArgumentPredicate"/> to one call.
/// </summary>
/// <remarks>
/// Three states rather than a bool, because "we could not decide" is not the
/// same answer as "no". A predicate abandoned mid-evaluation must not be
/// reported as a clean non-match: the caller supplies the argument, so a silent
/// give-up would let it choose which rules apply. See <see cref="PolicyEvaluator"/>
/// for what the evaluator does with <see cref="Indeterminate"/>.
/// </remarks>
internal enum PredicateResult
{
    /// <summary>The predicate does not hold for this call.</summary>
    NotSatisfied,

    /// <summary>The predicate holds.</summary>
    Satisfied,

    /// <summary>
    /// Evaluation was abandoned before an answer was reached, because a regular
    /// expression exceeded its time budget.
    /// </summary>
    Indeterminate,
}

/// <summary>
/// One assertion about a single argument of a tool call.
/// </summary>
/// <remarks>
/// A predicate names a value with <see cref="Path"/> and applies exactly one
/// operator to it:
///
/// <code>
/// args:
///   - path: $.limit
///     gt: 100
///   - path: $.path
///     not_prefix: /workspace/
/// </code>
///
/// One operator per predicate, rather than several combined, so that a rule
/// reads as a list of conditions and the <c>--explain</c> trail can name the one
/// that failed. Two conditions on the same value are two entries in the list.
///
/// <b>An argument that is not present never satisfies a predicate</b>, including
/// the negated ones. <c>not_prefix</c> asserts "there is a value, and it does not
/// start with this", not "there is no value starting with this". The alternative
/// - treating absence as satisfying a negation - makes a rule fire on evidence
/// that was never supplied, and "the argument was missing" is better handled by
/// the downstream server's own schema validation than guessed at here. When a
/// rule must also cover calls that omit the argument, follow it with a catch-all;
/// first-match-wins makes that composition explicit.
/// </remarks>
public sealed record ArgumentPredicate
{
    /// <summary>
    /// JSONPath to the value, e.g. <c>$.limit</c>. See <see cref="JsonPath"/> for
    /// the supported subset.
    /// </summary>
    [JsonPropertyName("path")]
    public string? Path { get; init; }

    /// <summary>Value equality: strings, numbers and booleans.</summary>
    [JsonPropertyName("eq")]
    public JsonElement? Eq { get; init; }

    /// <summary>Numeric: the value is greater than this.</summary>
    [JsonPropertyName("gt")]
    public double? Gt { get; init; }

    /// <summary>Numeric: the value is less than this.</summary>
    [JsonPropertyName("lt")]
    public double? Lt { get; init; }

    /// <summary>Regular expression, matched against a string value.</summary>
    [JsonPropertyName("matches")]
    public string? Matches { get; init; }

    /// <summary>The string value starts with this.</summary>
    [JsonPropertyName("prefix")]
    public string? Prefix { get; init; }

    /// <summary>The string value exists and does NOT start with this.</summary>
    [JsonPropertyName("not_prefix")]
    public string? NotPrefix { get; init; }

    /// <summary>The value equals one of these.</summary>
    [JsonPropertyName("in")]
    public IReadOnlyList<JsonElement>? In { get; init; }

    /// <summary>
    /// How long a <c>matches</c> pattern may run before it is abandoned.
    /// </summary>
    /// <remarks>
    /// A policy file is configuration, and a regex over a model-supplied
    /// argument can backtrack for an unbounded time. The timeout turns "the
    /// proxy hangs and every tool call stops" into a bounded per-call cost;
    /// <see cref="PredicateResult.Indeterminate"/> is what keeps that bound
    /// from becoming a bypass.
    /// </remarks>
    private static readonly TimeSpan _regexTimeout = TimeSpan.FromMilliseconds(100);

    /// <summary>Validates the predicate, throwing with the rule name in context.</summary>
    internal void Validate(string ruleName)
    {
        if (string.IsNullOrWhiteSpace(Path))
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has an argument predicate without a 'path'.");
        }

        if (!JsonPath.IsWellFormed(Path))
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has an unsupported argument path '{Path}'. " +
                "Supported forms are $.name, $.name.nested, $.name[0] and $['quoted name'].");
        }

        var operators = OperatorCount();

        if (operators == 0)
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has an argument predicate on '{Path}' with no operator. " +
                "Use one of eq, gt, lt, matches, prefix, not_prefix, in.");
        }

        if (operators > 1)
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has an argument predicate on '{Path}' with more than one " +
                "operator. Write one condition per list entry so a failing one can be named.");
        }

        if (In is { Count: 0 })
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has an empty 'in' list on '{Path}', which can never match.");
        }

        if (Matches is not null)
        {
            try
            {
                _ = Regex.IsMatch(string.Empty, Matches, RegexOptions.None, _regexTimeout);
            }
            catch (ArgumentException ex)
            {
                // Caught at load rather than on the first tool call: an invalid
                // pattern would otherwise throw inside the filter and turn a
                // policy typo into a failed tool call, mid-session.
                throw new PolicyException(
                    $"Rule '{ruleName}' has an invalid regular expression on '{Path}': {ex.Message}",
                    ex);
            }
        }
    }

    private int OperatorCount()
    {
        var count = 0;

        // Counted rather than short-circuited so "more than one operator" can be
        // reported as such instead of silently honouring the first.
        if (Eq is not null)
        {
            count++;
        }

        if (Gt is not null)
        {
            count++;
        }

        if (Lt is not null)
        {
            count++;
        }

        if (Matches is not null)
        {
            count++;
        }

        if (Prefix is not null)
        {
            count++;
        }

        if (NotPrefix is not null)
        {
            count++;
        }

        if (In is not null)
        {
            count++;
        }

        return count;
    }

    /// <summary>Applies the predicate to a call's arguments.</summary>
    internal PredicateResult Evaluate(IReadOnlyDictionary<string, JsonElement>? arguments)
    {
        // Path is non-null after Validate, which every rule goes through before
        // the evaluator will use it.
        if (!JsonPath.TryResolve(arguments, Path!, out var value))
        {
            return PredicateResult.NotSatisfied;
        }

        if (Eq is { } expected)
        {
            return From(JsonValueEquals(value, expected));
        }

        if (Gt is { } greaterThan)
        {
            return From(TryGetNumber(value, out var number) && number > greaterThan);
        }

        if (Lt is { } lessThan)
        {
            return From(TryGetNumber(value, out var number) && number < lessThan);
        }

        if (Matches is { } pattern)
        {
            return value.ValueKind is JsonValueKind.String
                ? MatchRegex(value, pattern)
                : PredicateResult.NotSatisfied;
        }

        if (Prefix is { } prefix)
        {
            return From(value.ValueKind is JsonValueKind.String &&
                        value.GetString()!.StartsWith(prefix, StringComparison.Ordinal));
        }

        if (NotPrefix is { } notPrefix)
        {
            return From(value.ValueKind is JsonValueKind.String &&
                        !value.GetString()!.StartsWith(notPrefix, StringComparison.Ordinal));
        }

        // Validate guarantees one operator is set, so this is the 'in' case.
        foreach (var candidate in In!)
        {
            if (JsonValueEquals(value, candidate))
            {
                return PredicateResult.Satisfied;
            }
        }

        return PredicateResult.NotSatisfied;
    }

    private static PredicateResult From(bool satisfied) =>
        satisfied ? PredicateResult.Satisfied : PredicateResult.NotSatisfied;

    private static PredicateResult MatchRegex(JsonElement value, string pattern)
    {
        try
        {
            // The static overload keeps a small compiled-pattern cache, so a
            // policy's patterns are compiled once rather than per call.
            return From(Regex.IsMatch(
                value.GetString()!, pattern, RegexOptions.None, _regexTimeout));
        }
        catch (RegexMatchTimeoutException)
        {
            // Reporting "no match" here would hand the caller a bypass: the
            // model chooses the argument and its length, so it could pad any
            // value until the deny rule containing this pattern gave up and the
            // call fell through to default-allow. An abandoned match is not
            // evidence of safety, so it is not an answer.
            return PredicateResult.Indeterminate;
        }
    }

    /// <summary>
    /// Compares two JSON values by kind and content.
    /// </summary>
    /// <remarks>
    /// Scalars only. Comparing objects or arrays structurally invites arguments
    /// about key order and numeric formatting that a policy file should not have
    /// to care about; a rule that needs to inspect inside a structure should path
    /// into it instead.
    /// </remarks>
    private static bool JsonValueEquals(JsonElement value, JsonElement expected) =>
        (value.ValueKind, expected.ValueKind) switch
        {
            (JsonValueKind.String, JsonValueKind.String) =>
                string.Equals(value.GetString(), expected.GetString(), StringComparison.Ordinal),
            (JsonValueKind.Number, JsonValueKind.Number) =>
                value.GetDouble() == expected.GetDouble(),
            (JsonValueKind.True, JsonValueKind.True) => true,
            (JsonValueKind.False, JsonValueKind.False) => true,
            (JsonValueKind.Null, JsonValueKind.Null) => true,
            _ => false,
        };

    private static bool TryGetNumber(JsonElement value, out double number)
    {
        if (value.ValueKind is JsonValueKind.Number)
        {
            number = value.GetDouble();
            return true;
        }

        number = 0;
        return false;
    }
}
