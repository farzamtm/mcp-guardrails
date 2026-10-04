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
/// <param name="Advisory">
/// True for a description match: reported for a person to read, but not a reason
/// to fail a scan, because prose that says "never deletes anything" matches too.
/// </param>
public sealed record AnnotationMismatch(string Field, string Verb, bool Advisory = false);

/// <summary>
/// Checks that a tool's <c>readOnlyHint</c> is plausible.
/// </summary>
/// <remarks>
/// Annotations are hints written by the server, and policy rules that match on
/// <c>readOnlyHint: true</c> trust them. A hostile or careless server can describe
/// its delete tool as read-only and walk it past every such rule; this makes that
/// measurable before the server is put behind the proxy.
///
/// Names are matched on the verb's base form only, the imperative a tool is
/// named with (<c>delete_record</c>, <c>moveFile</c>): inflected forms in a name
/// are nouns or adjectives far more often than commands - <c>get_updates</c>,
/// <c>list_sent_messages</c>, <c>search_deleted_items</c> are reads. A name match
/// fails the scan, so it has to be precise. Descriptions are matched on every
/// inflection, and a match there is advisory: prose that says "does not delete
/// anything" matches as readily as prose that admits it.
///
/// Whole words only, so <c>select_dropdown</c> is not "drop" and
/// <c>sender_name</c> is not "send". Linear in the length of the text.
/// </remarks>
public static class AnnotationCheck
{
    // Each verb a destructive or state-changing tool is named with: the forms a
    // name uses, and the inflections a description uses. "set" is names only -
    // in prose it is mostly a noun ("a set of rows") - and "exec" is the
    // abbreviation names use for execute. Deliberately absent: "run" and "post",
    // which name read-only tools as often as writes (run_query, get_post).
    private static readonly (string Verb, string[] InNames, string[] InDescriptions)[] _vocabulary =
    [
        ("delete", ["delete"], ["delete", "deletes", "deleted", "deleting"]),
        ("remove", ["remove"], ["remove", "removes", "removed", "removing"]),
        ("drop", ["drop"], ["drop", "drops", "dropped", "dropping"]),
        ("write", ["write"], ["write", "writes", "wrote", "written", "writing"]),
        ("update", ["update"], ["update", "updates", "updated", "updating"]),
        ("send", ["send"], ["send", "sends", "sent", "sending"]),
        ("execute", ["execute", "exec"], ["execute", "executes", "executed", "executing"]),
        ("create", ["create"], ["create", "creates", "created", "creating"]),
        ("edit", ["edit"], ["edit", "edits", "edited", "editing"]),
        ("move", ["move"], ["move", "moves", "moved", "moving"]),
        ("rename", ["rename"], ["rename", "renames", "renamed", "renaming"]),
        ("insert", ["insert"], ["insert", "inserts", "inserted", "inserting"]),
        ("modify", ["modify"], ["modify", "modifies", "modified", "modifying"]),
        ("overwrite", ["overwrite"], ["overwrite", "overwrites", "overwrote", "overwritten", "overwriting"]),
        ("truncate", ["truncate"], ["truncate", "truncates", "truncated", "truncating"]),
        ("purge", ["purge"], ["purge", "purges", "purged", "purging"]),
        ("kill", ["kill"], ["kill", "kills", "killed", "killing"]),
        ("set", ["set"], []),
    ];

    /// <summary>Every word that suggests a write in a description, mapped to the verb reported for it.</summary>
    public static IReadOnlyDictionary<string, string> Verbs { get; } = Build(entry => entry.InDescriptions);

    /// <summary>Every word that suggests a write in a name, mapped to the verb reported for it.</summary>
    public static IReadOnlyDictionary<string, string> NameVerbs { get; } = Build(entry => entry.InNames);

    // Anything longer than the longest form cannot be in the vocabulary, and
    // skipping it keeps the lowercase copy in Lookup small.
    private static readonly int _longestForm = Verbs.Keys.Concat(NameVerbs.Keys).Max(form => form.Length);

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

        if (FirstVerb(tool.Name, inName: true) is { } inName)
        {
            mismatches.Add(new AnnotationMismatch("name", inName));
        }

        if (FirstVerb(tool.Description, inName: false) is { } inDescription)
        {
            mismatches.Add(new AnnotationMismatch("description", inDescription, Advisory: true));
        }

        return mismatches;
    }

    /// <summary>The verb of the first write-suggesting word in <paramref name="text"/>, or null.</summary>
    /// <param name="text">A tool name or description.</param>
    /// <param name="inName">
    /// True for a name: split on camelCase too, and match base forms only. Prose
    /// is not camel-split - splitting "iPhone" would only invent words.
    /// </param>
    internal static string? FirstVerb(string? text, bool inName)
    {
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        var vocabulary = inName ? NameVerbs : Verbs;
        var start = -1;
        for (var i = 0; i <= text.Length; i++)
        {
            var boundary = i == text.Length || !char.IsLetter(text[i]) ||
                           (inName && i > 0 && char.IsUpper(text[i]) && char.IsLower(text[i - 1]));

            if (boundary && start >= 0)
            {
                if (Lookup(text.AsSpan(start, i - start), vocabulary) is { } verb)
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

    private static string? Lookup(ReadOnlySpan<char> word, IReadOnlyDictionary<string, string> vocabulary)
    {
        if (word.Length > _longestForm)
        {
            return null;
        }

        Span<char> lower = stackalloc char[word.Length];
        word.ToLowerInvariant(lower);

        return vocabulary.TryGetValue(lower.ToString(), out var verb) ? verb : null;
    }

    private static Dictionary<string, string> Build(Func<(string Verb, string[] InNames, string[] InDescriptions), string[]> forms)
    {
        var verbs = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var entry in _vocabulary)
        {
            foreach (var form in forms(entry))
            {
                verbs[form] = entry.Verb;
            }
        }

        return verbs;
    }
}
