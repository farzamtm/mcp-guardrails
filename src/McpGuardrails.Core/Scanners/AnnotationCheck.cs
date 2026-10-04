using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Scanners;

/// <summary>
/// A tool that declares itself read-only while its name or description says it
/// changes something.
/// </summary>
/// <param name="Field"><c>name</c> or <c>description</c>.</param>
/// <param name="Verb">
/// The word that suggested a write, as it appears in <see cref="AnnotationCheck.Verbs"/>'s
/// vocabulary - never copied from the definition, so printing it repeats nothing
/// the server wrote.
/// </param>
public sealed record AnnotationMismatch(string Field, string Verb);

/// <summary>
/// Checks that a tool's <c>readOnlyHint</c> is plausible.
/// </summary>
/// <remarks>
/// Annotations are hints written by the server, and policy rules that match on
/// <c>readOnlyHint: true</c> trust them. A hostile or careless server can describe
/// its delete tool as read-only and walk it past every such rule; this makes that
/// measurable before the server is put behind the proxy.
///
/// Whole words only, from a fixed list of inflections, so <c>select_dropdown</c>
/// is not "drop" and <c>sender_name</c> is not "send". A description that says
/// "does not delete anything" is still reported: this is a report a person reads,
/// so recall matters more than precision. Linear in the length of the text.
/// </remarks>
public static class AnnotationCheck
{
    /// <summary>Every word that suggests a write, mapped to the verb reported for it.</summary>
    public static IReadOnlyDictionary<string, string> Verbs { get; } = BuildVerbs();

    /// <summary>
    /// The mismatches in <paramref name="tool"/>: empty unless it declares
    /// <c>readOnlyHint: true</c>.
    /// </summary>
    /// <remarks>
    /// At most one per field - the first verb found - because one is enough to
    /// make a person look, and the name of the verb is all the report says.
    /// </remarks>
    public static IReadOnlyList<AnnotationMismatch> Check(Tool tool)
    {
        ArgumentNullException.ThrowIfNull(tool);

        if (tool.Annotations?.ReadOnlyHint is not true)
        {
            return [];
        }

        var mismatches = new List<AnnotationMismatch>();

        if (FirstVerb(tool.Name, splitCamelCase: true) is { } inName)
        {
            mismatches.Add(new AnnotationMismatch("name", inName));
        }

        // Not camel-split: prose has no camelCase, and splitting "iPhone" would
        // only invent words.
        if (FirstVerb(tool.Description, splitCamelCase: false) is { } inDescription)
        {
            mismatches.Add(new AnnotationMismatch("description", inDescription));
        }

        return mismatches;
    }

    /// <summary>The verb of the first write-suggesting word in <paramref name="text"/>, or null.</summary>
    internal static string? FirstVerb(string? text, bool splitCamelCase)
    {
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        var start = -1;
        for (var i = 0; i <= text.Length; i++)
        {
            var boundary = i == text.Length || !char.IsLetter(text[i]) ||
                           (splitCamelCase && i > 0 && char.IsUpper(text[i]) && char.IsLower(text[i - 1]));

            if (boundary && start >= 0)
            {
                if (Lookup(text.AsSpan(start, i - start)) is { } verb)
                {
                    return verb;
                }

                start = -1;
            }

            if (i < text.Length && char.IsLetter(text[i]) && start < 0)
            {
                start = i;
            }
        }

        return null;
    }

    private static string? Lookup(ReadOnlySpan<char> word)
    {
        // The longest form in the vocabulary is "executing"; anything longer is
        // not in it, and skipping it keeps the lowercase copy below small.
        if (word.Length > 9)
        {
            return null;
        }

        Span<char> lower = stackalloc char[word.Length];
        word.ToLowerInvariant(lower);

        return Verbs.TryGetValue(lower.ToString(), out var verb) ? verb : null;
    }

    private static Dictionary<string, string> BuildVerbs()
    {
        // The verbs a destructive or state-changing tool is named with, and the
        // inflections a name or description actually uses.
        (string Verb, string[] Forms)[] vocabulary =
        [
            ("delete", ["delete", "deletes", "deleted", "deleting"]),
            ("remove", ["remove", "removes", "removed", "removing"]),
            ("drop", ["drop", "drops", "dropped", "dropping"]),
            ("write", ["write", "writes", "wrote", "written", "writing"]),
            ("update", ["update", "updates", "updated", "updating"]),
            ("send", ["send", "sends", "sent", "sending"]),
            ("execute", ["execute", "executes", "executed", "executing"]),
        ];

        var verbs = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (verb, forms) in vocabulary)
        {
            foreach (var form in forms)
            {
                verbs[form] = verb;
            }
        }

        return verbs;
    }
}
