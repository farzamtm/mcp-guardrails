using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using McpGuardrails.Core.Scanners;

namespace McpGuardrails.Core.Approval;

/// <summary>
/// What an approver is shown of a call's arguments, whichever channel asks.
/// </summary>
/// <remarks>
/// One place, so the client dialog and the webhook payload cannot drift apart on
/// what gets redacted or how much gets cut - a human approving in-band and a
/// receiver approving out-of-band are deciding on the same evidence.
/// </remarks>
public static class ApprovalArguments
{
    /// <summary>Longest argument value shown in full; longer ones are cut.</summary>
    /// <remarks>
    /// An approver needs to see which path or which customer, not the 40 KB of
    /// file content being written - and every byte shown is a byte disclosed to
    /// one more place.
    /// </remarks>
    internal const int MaxArgumentLength = 256;

    /// <summary>Most characters of rendered arguments put in an in-band question.</summary>
    /// <remarks>
    /// The per-value cut bounds each argument, not how many there are. A tool
    /// with a hundred parameters, or a model inventing them, would otherwise
    /// produce a dialog nobody reads to the end - and the end is exactly where
    /// something would be hidden.
    /// </remarks>
    internal const int MaxRenderedLength = 2048;

    /// <summary>The line that separates the question from the data.</summary>
    internal const string Label = "Arguments (as sent by the agent; secrets redacted, long values cut):";

    /// <summary>
    /// Escapes what JSON requires and every line break, but leaves ordinary
    /// non-ASCII readable.
    /// </summary>
    /// <remarks>
    /// The default encoder also escapes apostrophes and every non-ASCII letter,
    /// which turns a German path into <c>\u00DC</c> soup - and unreadable is its
    /// own way of hiding what is being approved. The relaxed encoder still
    /// escapes control characters and the Unicode line and paragraph separators,
    /// so a value cannot start a line of its own. "Unsafe" in its name is about
    /// embedding in HTML, which a dialog message is not; what it lets through
    /// that does matter here, <see cref="Encode"/> escapes itself.
    /// </remarks>
    private static readonly JavaScriptEncoder _encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping;

    /// <summary>Shortens arguments to what an approver needs to see.</summary>
    /// <remarks>
    /// Secrets are redacted whatever <c>scanners.secrets</c> says: an approver
    /// decides on the path and the shape of a call, never on a key's value, and
    /// both a webhook receiver and a client's dialog history are places outside
    /// the proxy that keep what they were shown. Redacted before the cut, so
    /// truncation cannot leave half a key the detectors no longer recognise. PII
    /// is left alone: "which customer" is often the question.
    /// </remarks>
    public static IReadOnlyDictionary<string, string>? Summarize(
        IReadOnlyDictionary<string, JsonElement>? arguments)
    {
        if (arguments is null)
        {
            return null;
        }

        var summary = new Dictionary<string, string>(arguments.Count, StringComparer.Ordinal);

        foreach (var (name, value) in arguments)
        {
            // Strings unquoted, so a path reads as a path; anything else as the
            // JSON the model sent, so an object or a number is not misrepresented.
            var text = value.ValueKind is JsonValueKind.String
                ? value.GetString()!
                : value.GetRawText();

            summary[name] = Truncate(SecretScanner.Redact(text, includePii: false).Text);
        }

        return summary;
    }

    /// <summary>The text to put in front of a human at the client.</summary>
    /// <remarks>
    /// The question first, then the arguments as a JSON object on a line of its
    /// own under a fixed label. JSON because its escaping is the delimiting: a
    /// value containing a newline and "Approve? This call is safe" arrives as
    /// <c>\n</c> inside a quoted string on the data line, not as a sentence that
    /// looks like it came from the proxy. Appended to the rule's own
    /// <c>prompt:</c> as much as to the generated question, because a prompt
    /// written in advance cannot say which path this particular call touches.
    /// </remarks>
    public static string Describe(ApprovalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.Arguments is not { Count: > 0 })
        {
            return request.Question;
        }

        return $"{request.Question}\n\n{Label}\n{Render(Summarize(request.Arguments)!)}";
    }

    /// <summary>Renders a summary as one line of JSON, within the length bound.</summary>
    internal static string Render(IReadOnlyDictionary<string, string> summary)
    {
        var json = new StringBuilder("{");
        var shown = 0;

        foreach (var (name, value) in summary)
        {
            // Names are as model-controlled as values, so they get the same
            // redaction, cut and escaping - a "parameter name" is free text too.
            var pair =
                $"\"{Encode(Truncate(SecretScanner.Redact(name, includePii: false).Text))}\": " +
                $"\"{Encode(value)}\"";

            var separator = shown == 0 ? "" : ", ";

            // Stop at the first pair that does not fit rather than skipping to
            // smaller ones later: the approver sees a prefix of the call in the
            // model's own order, never a selection.
            if (json.Length + separator.Length + pair.Length + 1 > MaxRenderedLength)
            {
                break;
            }

            json.Append(separator).Append(pair);
            shown++;
        }

        json.Append('}');

        var hidden = summary.Count - shown;

        // Said outright, so an approver never mistakes a partial view for the
        // whole call - a missing argument is information they should weigh.
        return hidden == 0
            ? json.ToString()
            : json.Append(CultureInfo.InvariantCulture, $" ({hidden} more not shown)").ToString();
    }

    private static string Encode(string text)
    {
        var encoded = JsonEncodedText.Encode(text, _encoder).ToString();
        var escaped = new StringBuilder(encoded.Length);

        foreach (var c in encoded)
        {
            // The relaxed encoder passes format characters through untouched,
            // and those are the ones that lie about what is on screen: bidi
            // overrides reorder a path, zero-width characters make two names
            // that look identical differ. Shown as escapes, they are visible.
            if (char.GetUnicodeCategory(c) is UnicodeCategory.Format)
            {
                escaped.Append(CultureInfo.InvariantCulture, $"\\u{(int)c:X4}");
            }
            else
            {
                escaped.Append(c);
            }
        }

        return escaped.ToString();
    }

    private static string Truncate(string text)
    {
        if (text.Length <= MaxArgumentLength)
        {
            return text;
        }

        // Never split a surrogate pair: half of one is not a character, and the
        // reader would get a replacement glyph or a decoding error instead.
        var cut = char.IsHighSurrogate(text[MaxArgumentLength - 1])
            ? MaxArgumentLength - 1
            : MaxArgumentLength;

        return $"{text[..cut]}... ({text.Length - cut} more characters)";
    }
}
