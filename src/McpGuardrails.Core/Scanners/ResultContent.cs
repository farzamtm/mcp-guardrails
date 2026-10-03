using System.Globalization;
using System.Text.Json;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Scanners;

/// <summary>
/// What the result scanners agree a tool result is made of, and how they word a
/// refusal.
/// </summary>
/// <remarks>
/// Shared by the injection and secret gates so the two cannot drift apart on
/// which parts of a result the model reads. A shape one of them learned to look
/// inside and the other did not would be a place to put whatever the other one
/// exists to catch.
/// </remarks>
internal static class ResultContent
{
    /// <summary>The text of a content block, or null for a shape that carries none.</summary>
    /// <remarks>
    /// Text blocks and embedded text resources are the two shapes model-readable
    /// prose arrives in. Images and audio are not scanned: reading them would
    /// mean decoding attacker-supplied binary, which is a larger attack surface
    /// than the one being defended, and the heuristics here have nothing to say
    /// about pixels.
    /// </remarks>
    public static string? TextOf(ContentBlock block) => block switch
    {
        TextContentBlock text => text.Text,
        EmbeddedResourceBlock { Resource: TextResourceContents resource } => resource.Text,
        _ => null,
    };

    /// <summary>
    /// A copy of a block carrying <paramref name="text"/> in place of its own.
    /// </summary>
    /// <param name="block">A block <see cref="TextOf"/> returned text for.</param>
    /// <param name="text">The replacement text.</param>
    /// <remarks>
    /// The copy keeps the original's annotations and metadata, so a client that
    /// routes on audience or priority sees the replacement exactly where it
    /// would have seen the original.
    /// </remarks>
    public static ContentBlock WithText(ContentBlock block, string text) => block switch
    {
        EmbeddedResourceBlock { Resource: TextResourceContents resource } embedded => new EmbeddedResourceBlock
        {
            Resource = new TextResourceContents
            {
                Uri = resource.Uri,
                MimeType = resource.MimeType,
                Meta = resource.Meta,
                Text = text,
            },
            Annotations = embedded.Annotations,
            Meta = embedded.Meta,
        },

        // TextOf answers only for these two shapes, so this arm is a text block.
        _ => new TextContentBlock
        {
            Text = text,
            Annotations = block.Annotations,
            Meta = block.Meta,
        },
    };

    /// <summary>The structured payload, or null when the result has none.</summary>
    /// <remarks>
    /// Undefined is what a default JsonElement carries, and asking one for
    /// anything throws rather than returning nothing: a result built without
    /// structured content must not take the proxy down on the way back.
    /// </remarks>
    public static JsonElement? StructuredOf(CallToolResult result) =>
        result.StructuredContent is { ValueKind: not JsonValueKind.Undefined } structured ? structured : null;

    /// <summary>Every property name and string value in a JSON value, decoded, in document order.</summary>
    /// <remarks>
    /// Decoded is the point. The raw text of <c>"ig\u200Bnore"</c> or
    /// <c>"all\nprevious"</c> is a run of letters a token scan reads as one
    /// harmless word, while the model reads the value the escape stands for. Names
    /// as well as values, because a property called
    /// <c>ignore_previous_instructions</c> reaches the model just as well.
    ///
    /// Each string on its own rather than joined, for the reason blocks are
    /// scanned separately: a trigger at the end of one value must not pair with a
    /// target at the start of the next and invent a match that is in neither.
    ///
    /// Recursion is bounded by the JSON reader's own depth limit, which the value
    /// already passed when it was parsed. A default <see cref="JsonElement"/> is
    /// Undefined and yields nothing.
    /// </remarks>
    public static IEnumerable<string> StringsOf(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    yield return property.Name;

                    foreach (var text in StringsOf(property.Value))
                    {
                        yield return text;
                    }
                }

                break;

            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    foreach (var text in StringsOf(item))
                    {
                        yield return text;
                    }
                }

                break;

            case JsonValueKind.String:
                yield return element.GetString()!;
                break;
        }
    }

    /// <summary>
    /// The tool error a scanner replaces a withheld result with.
    /// </summary>
    /// <param name="original">The result being withheld; only its metadata is kept.</param>
    /// <param name="scanner">The scanner's policy name, e.g. <c>injection</c>.</param>
    /// <param name="toolName">Client-visible tool name.</param>
    /// <param name="finding">What the output did, e.g. "matched 1 prompt-injection heuristic (x)".</param>
    /// <param name="advice">What the model should do instead.</param>
    /// <remarks>
    /// Every scanner says the content was withheld rather than that the tool
    /// failed, because an agent that believes a tool is broken reaches for a
    /// different one to fetch the same content. Result-level <c>_meta</c> is
    /// protocol bookkeeping rather than content, so it survives the refusal as
    /// it would any other rebuild.
    /// </remarks>
    public static CallToolResult Blocked(
        CallToolResult original,
        string scanner,
        string toolName,
        string finding,
        string advice)
    {
        var text =
            $"Blocked by guardrails scanner '{scanner}': the output of '{toolName}' " +
            $"{finding}, so it was withheld and you have not seen it. {advice}";

        return new CallToolResult
        {
            IsError = true,
            Meta = original.Meta,
            Content = [new TextContentBlock { Text = text }],
        };
    }

    /// <summary>"1 thing" or "N things".</summary>
    /// <remarks>
    /// "1 sensitive values" reads as a mistake, and these strings are shown to a
    /// human as often as to a model.
    /// </remarks>
    public static string CountOf(int count, string singular, string plural) =>
        count == 1 ? $"1 {singular}" : $"{count.ToString(CultureInfo.InvariantCulture)} {plural}";

    /// <summary>
    /// Both lists in order, the second's items after the first's, without
    /// duplicates.
    /// </summary>
    /// <remarks>
    /// The merge both scanners' reports need: names in the order first seen, so
    /// the audit log reads the same way for the same result every time.
    /// </remarks>
    public static List<string> OrderedUnion(IReadOnlyList<string> first, IReadOnlyList<string> second)
    {
        var merged = new List<string>(first);

        foreach (var item in second)
        {
            if (!merged.Contains(item))
            {
                merged.Add(item);
            }
        }

        return merged;
    }
}
