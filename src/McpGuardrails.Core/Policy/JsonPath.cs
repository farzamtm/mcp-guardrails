using System.Text.Json;

namespace McpGuardrails.Core.Policy;

/// <summary>
/// Resolves a small JSONPath subset against a tool call's arguments.
/// </summary>
/// <remarks>
/// Supported: <c>$.a.b</c>, the equivalent bare form <c>a.b</c>, array indexing
/// <c>$.files[0]</c>, and quoted keys <c>$['content-type']</c> for names that
/// contain a dot or a bracket.
///
/// Deliberately NOT supported: wildcards, recursive descent (<c>..</c>), slices,
/// filter expressions. The spec calls for a purpose-built evaluator covering the
/// predicates actually needed, and the reasoning holds here too - every JSONPath
/// library worth using binds by reflection or compiles expressions, both of which
/// Native AOT trims. A hundred lines of span-walking removes that dependency risk
/// entirely, and the unsupported syntax is rejected at policy load time rather
/// than silently matching nothing at runtime.
///
/// Nothing here allocates: property names are compared as spans, so evaluating a
/// predicate on every tool call costs no garbage.
/// </remarks>
internal static class JsonPath
{
    /// <summary>
    /// Resolves <paramref name="path"/> against <paramref name="arguments"/>.
    /// </summary>
    /// <returns>
    /// False when the path does not exist in these arguments, which callers must
    /// treat as "the predicate does not hold" rather than as an error. An
    /// argument the model did not send is not evidence of anything.
    /// </returns>
    internal static bool TryResolve(
        IReadOnlyDictionary<string, JsonElement>? arguments,
        string path,
        out JsonElement value)
    {
        value = default;

        if (arguments is null)
        {
            return false;
        }

        var rest = path.AsSpan();

        if (rest.Length > 0 && rest[0] == '$')
        {
            rest = rest[1..];
        }

        var resolved = false;

        while (!rest.IsEmpty)
        {
            if (!TryTakeSegment(ref rest, allowBare: !resolved, out var name, out var index))
            {
                return false;
            }

            if (!resolved)
            {
                // The root is the arguments object, which is a dictionary rather
                // than a JsonElement, so the first hop is looked up separately.
                if (index >= 0 || !TryGetMember(arguments, name, out value))
                {
                    return false;
                }

                resolved = true;
                continue;
            }

            if (index >= 0)
            {
                if (value.ValueKind is not JsonValueKind.Array || index >= value.GetArrayLength())
                {
                    return false;
                }

                value = value[index];
                continue;
            }

            if (value.ValueKind is not JsonValueKind.Object ||
                !value.TryGetProperty(name, out value))
            {
                return false;
            }
        }

        // A bare "$" names the whole argument object. Matching on it is not
        // meaningful for any of the operators, so treat it as unresolved.
        return resolved;
    }

    /// <summary>True when the path is syntactically valid.</summary>
    /// <remarks>
    /// Checked when the policy loads, so a typo is a startup error naming the
    /// rule rather than a predicate that silently never matches. A policy rule
    /// that quietly does nothing is the worst outcome available here: the
    /// operator believes a guardrail exists when it does not.
    /// </remarks>
    internal static bool IsWellFormed(string path)
    {
        var rest = path.AsSpan();

        if (rest.Length > 0 && rest[0] == '$')
        {
            rest = rest[1..];
        }

        var segments = 0;

        while (!rest.IsEmpty)
        {
            if (!TryTakeSegment(ref rest, allowBare: segments == 0, out _, out var index))
            {
                return false;
            }

            // "$[0]" would index the arguments object, which is always a mapping
            // of named arguments. Rejecting it is clearer than resolving to
            // nothing forever.
            if (segments == 0 && index >= 0)
            {
                return false;
            }

            segments++;
        }

        return segments > 0;
    }

    /// <summary>
    /// Consumes one segment from the front of <paramref name="rest"/>.
    /// </summary>
    /// <param name="allowBare">
    /// True for the first segment, where the leading dot is optional so both
    /// <c>$.limit</c> and <c>limit</c> work.
    /// </param>
    /// <param name="name">The property name, empty for an index segment.</param>
    /// <param name="index">The array index, or -1 for a property segment.</param>
    private static bool TryTakeSegment(
        ref ReadOnlySpan<char> rest,
        bool allowBare,
        out ReadOnlySpan<char> name,
        out int index)
    {
        name = default;
        index = -1;

        if (rest[0] == '[')
        {
            return TryTakeBracketed(ref rest, out name, out index);
        }

        if (rest[0] == '.')
        {
            rest = rest[1..];
        }
        else if (!allowBare)
        {
            // Two names with no separator, e.g. "$.a b" after a quoted segment.
            return false;
        }

        var end = rest.IndexOfAny('.', '[');
        if (end < 0)
        {
            end = rest.Length;
        }

        name = rest[..end];
        rest = rest[end..];

        // A bare '*' is rejected rather than read as a property literally called
        // "*". In JSONPath it means "every child", so anyone writing $.files[*]
        // or $.* expects a wildcard; treating it as a name would give them a rule
        // that silently never matches. Quote it - $['*'] - to mean the character.
        return !name.IsEmpty && !name.Contains('*');
    }

    private static bool TryTakeBracketed(
        ref ReadOnlySpan<char> rest,
        out ReadOnlySpan<char> name,
        out int index)
    {
        name = default;
        index = -1;

        var close = rest.IndexOf(']');
        if (close < 0)
        {
            return false;
        }

        var inner = rest[1..close];
        rest = rest[(close + 1)..];

        if (inner.Length >= 2 &&
            (inner[0] == '\'' || inner[0] == '"') &&
            inner[^1] == inner[0])
        {
            name = inner[1..^1];
            return !name.IsEmpty;
        }

        // Unsigned only: negative indices would need a length to resolve against,
        // and "last element" is not a predicate anyone has asked for yet.
        return int.TryParse(inner, out index) && index >= 0;
    }

    /// <summary>
    /// Looks a name up in the arguments without allocating a string for it.
    /// </summary>
    /// <remarks>
    /// A linear scan beats materialising the span as a dictionary key: argument
    /// objects have a handful of entries, and this runs for every predicate of
    /// every rule on every call.
    /// </remarks>
    private static bool TryGetMember(
        IReadOnlyDictionary<string, JsonElement> arguments,
        ReadOnlySpan<char> name,
        out JsonElement value)
    {
        foreach (var (key, candidate) in arguments)
        {
            if (name.SequenceEqual(key))
            {
                value = candidate;
                return true;
            }
        }

        value = default;
        return false;
    }
}
