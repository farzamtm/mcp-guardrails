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
/// One operator per predicate so that the <c>--explain</c> trail can name the
/// condition that failed; two conditions on one value are two list entries. The
/// semantics operators do NOT have - absent arguments, string comparison, path
/// syntax - are documented once in the README rather than restated here.
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

    /// <summary>The string value starts with this, compared literally.</summary>
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
    /// A policy file is configuration, and a regular expression over a
    /// model-supplied argument can backtrack for an unbounded time. The timeout
    /// turns "the proxy hangs and every tool call stops" into a bounded per-call
    /// cost; <see cref="Result.Indeterminate"/> is what keeps that
    /// bound from becoming a bypass.
    /// </remarks>
    internal static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// The resolved form of this predicate: a validated path and exactly one
    /// operation, worked out once instead of re-derived on every call.
    /// </summary>
    /// <remarks>
    /// Resolving at load is what removes the "trust that Validate ran" contract
    /// the evaluation path used to depend on. It also means a <c>matches</c>
    /// pattern is compiled once per policy, rather than fetched from the
    /// process-global <see cref="Regex"/> cache - which is small, shared with
    /// every other component in the process, and therefore no guarantee at all.
    /// </remarks>
    private sealed record Resolved(string Path, PredicateOperation Operation);

    private Resolved? _resolved;

    /// <remarks>
    /// A predicate built in code and never validated resolves on first use and
    /// throws <see cref="PolicyException"/> if it is malformed. The rule name is
    /// unavailable on that path, but a configuration error naming the problem
    /// beats a <see cref="NullReferenceException"/> inside the call filter.
    /// </remarks>
    private Resolved Current => _resolved ??= Resolve("(unvalidated)");

    /// <summary>Validates the predicate, throwing with the rule name in context.</summary>
    public void Validate(string ruleName) => _resolved = Resolve(ruleName);

    /// <summary>Applies the predicate to a call's arguments.</summary>
    internal PredicateResult Evaluate(IReadOnlyDictionary<string, JsonElement>? arguments)
    {
        var resolved = Current;

        return JsonPath.TryResolve(arguments, resolved.Path, out var value)
            ? resolved.Operation.Apply(value)
            : PredicateResult.NotSatisfied;
    }

    private Resolved Resolve(string ruleName)
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

        return new Resolved(Path, ResolveOperation(ruleName));
    }

    /// <remarks>
    /// The one place the operator set is enumerated. Adding an operator means a
    /// property, an arm here and a subclass of <see cref="PredicateOperation"/>;
    /// the evaluation path needs no change, and cannot be left out of date.
    /// </remarks>
    private PredicateOperation ResolveOperation(string ruleName)
    {
        PredicateOperation? operation = null;

        // Every operator is examined rather than short-circuited on the first
        // hit, so "more than one operator" is reported as such instead of the
        // others being silently ignored.
        if (Eq is { } expected)
        {
            operation = Only(operation, new EqualsOperation(expected), ruleName);
        }

        if (Gt is { } greaterThan)
        {
            operation = Only(operation, new GreaterThanOperation(greaterThan), ruleName);
        }

        if (Lt is { } lessThan)
        {
            operation = Only(operation, new LessThanOperation(lessThan), ruleName);
        }

        if (Matches is { } pattern)
        {
            operation = Only(operation, CompileRegex(pattern, ruleName), ruleName);
        }

        if (Prefix is { } prefix)
        {
            operation = Only(
                operation,
                new PrefixOperation(RequireNonEmpty(prefix, "prefix", ruleName)),
                ruleName);
        }

        if (NotPrefix is { } notPrefix)
        {
            operation = Only(
                operation,
                new NotPrefixOperation(RequireNonEmpty(notPrefix, "not_prefix", ruleName)),
                ruleName);
        }

        if (In is { } candidates)
        {
            if (candidates.Count == 0)
            {
                throw new PolicyException(
                    $"Rule '{ruleName}' has an empty 'in' list on '{Path}', which can never match.");
            }

            operation = Only(operation, new InOperation(candidates), ruleName);
        }

        return operation ?? throw new PolicyException(
            $"Rule '{ruleName}' has an argument predicate on '{Path}' with no operator. " +
            "Use one of eq, gt, lt, matches, prefix, not_prefix, in. A null value " +
            "(for example 'eq: null') is not a comparison and reads as no operator.");
    }

    private PredicateOperation Only(
        PredicateOperation? existing,
        PredicateOperation candidate,
        string ruleName) =>
        existing is null
            ? candidate
            : throw new PolicyException(
                $"Rule '{ruleName}' has an argument predicate on '{Path}' with more than one " +
                "operator. Write one condition per list entry so a failing one can be named.");

    /// <remarks>
    /// An empty prefix is always true and an empty not_prefix is never true, so
    /// both are rules that quietly do nothing - the worst outcome available to a
    /// policy engine, because the operator believes a guardrail exists.
    /// </remarks>
    private string RequireNonEmpty(string value, string operatorName, string ruleName) =>
        value.Length > 0
            ? value
            : throw new PolicyException(
                $"Rule '{ruleName}' has an empty '{operatorName}' on '{Path}'. " +
                (operatorName == "prefix"
                    ? "It would match every string value."
                    : "It can never match."));

    /// <remarks>
    /// Compiled at load rather than on the first tool call: an invalid pattern
    /// would otherwise throw inside the filter and turn a policy typo into a
    /// failed tool call, mid-session.
    /// </remarks>
    private RegexOperation CompileRegex(string pattern, string ruleName)
    {
        try
        {
            return new RegexOperation(new Regex(pattern, RegexOptions.None, RegexTimeout));
        }
        catch (ArgumentException ex)
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has an invalid regular expression on '{Path}': {ex.Message}",
                ex);
        }
    }
}

/// <summary>
/// One resolved operator, ready to apply.
/// </summary>
/// <remarks>
/// A type per operator rather than an enum plus seven optional operands: each
/// subclass holds exactly the data it needs, non-nullable, so the evaluation
/// path has nothing to assert about and no null-forgiving operator in it.
/// </remarks>
internal abstract class PredicateOperation
{
    internal abstract PredicateResult Apply(JsonElement value);

    private protected static PredicateResult From(bool satisfied) =>
        satisfied ? PredicateResult.Satisfied : PredicateResult.NotSatisfied;

    /// <summary>
    /// Compares two JSON values by kind and content.
    /// </summary>
    /// <remarks>
    /// Scalars only. Comparing objects or arrays structurally invites arguments
    /// about key order and numeric formatting that a policy file should not have
    /// to care about; a rule that needs to inspect inside a structure should path
    /// into it instead.
    /// </remarks>
    private protected static bool JsonValueEquals(JsonElement value, JsonElement expected) =>
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

    /// <remarks>
    /// No coercion: a string that looks like a number is still a string, and
    /// treating it as one would let <c>limit: "1000"</c> slip past a gt rule.
    /// </remarks>
    private protected static bool TryGetNumber(JsonElement value, out double number)
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

internal sealed class EqualsOperation(JsonElement expected) : PredicateOperation
{
    internal override PredicateResult Apply(JsonElement value) =>
        From(JsonValueEquals(value, expected));
}

internal sealed class GreaterThanOperation(double bound) : PredicateOperation
{
    internal override PredicateResult Apply(JsonElement value) =>
        From(TryGetNumber(value, out var number) && number > bound);
}

internal sealed class LessThanOperation(double bound) : PredicateOperation
{
    internal override PredicateResult Apply(JsonElement value) =>
        From(TryGetNumber(value, out var number) && number < bound);
}

internal sealed class PrefixOperation(string prefix) : PredicateOperation
{
    internal override PredicateResult Apply(JsonElement value) =>
        From(value.ValueKind is JsonValueKind.String &&
             value.GetString()!.StartsWith(prefix, StringComparison.Ordinal));
}

internal sealed class NotPrefixOperation(string prefix) : PredicateOperation
{
    internal override PredicateResult Apply(JsonElement value) =>
        From(value.ValueKind is JsonValueKind.String &&
             !value.GetString()!.StartsWith(prefix, StringComparison.Ordinal));
}

internal sealed class InOperation(IReadOnlyList<JsonElement> candidates) : PredicateOperation
{
    internal override PredicateResult Apply(JsonElement value)
    {
        foreach (var candidate in candidates)
        {
            if (JsonValueEquals(value, candidate))
            {
                return PredicateResult.Satisfied;
            }
        }

        return PredicateResult.NotSatisfied;
    }
}

internal sealed class RegexOperation(Regex pattern) : PredicateOperation
{
    internal override PredicateResult Apply(JsonElement value)
    {
        if (value.ValueKind is not JsonValueKind.String)
        {
            return PredicateResult.NotSatisfied;
        }

        try
        {
            return From(pattern.IsMatch(value.GetString()!));
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
}
