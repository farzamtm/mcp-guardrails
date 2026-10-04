namespace McpGuardrails.Core.Text;

/// <summary>
/// Makes text a server chose safe to print to a terminal.
/// </summary>
/// <remarks>
/// Tool names, schema keys and error messages are written by downstream
/// servers, and the commands that print them (<c>scan</c>, <c>pins</c>,
/// <c>list-upstream</c>, any failure message) are run in a terminal, often
/// against a server nobody trusts yet. An ESC sequence there can clear the
/// screen, forge a "Clean" line, set the window title or write the clipboard
/// (OSC 52); a bidi override or zero-width character can make one name read as
/// another. Each such character is replaced with <c>?</c>, so the output stays
/// one character per character and nothing is silently dropped.
///
/// Linear in the length of the text, and the input is returned unchanged when
/// nothing needs replacing.
/// </remarks>
public static class TerminalText
{
    private const char _replacement = '?';

    /// <summary>
    /// <paramref name="value"/> with every control, bidi-control, zero-width and
    /// line-separator character replaced - line breaks included, so the result is
    /// one line.
    /// </summary>
    public static string Printable(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return Replace(value, keepNewlines: false);
    }

    /// <summary>
    /// Like <see cref="Printable"/>, but keeps line breaks (normalized to
    /// <c>\n</c>): for multi-line messages the proxy itself formats, where only
    /// the parts a server wrote could carry anything else.
    /// </summary>
    public static string PrintableLines(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return Replace(value.ReplaceLineEndings("\n"), keepNewlines: true);
    }

    /// <summary>True when <paramref name="c"/> must not reach a terminal as itself.</summary>
    internal static bool IsUnsafe(char c) =>
        char.IsControl(c) // C0, DEL and C1, including ESC and the 8-bit CSI
        || c is '\u061C' // Arabic letter mark
        || c is >= '\u200B' and <= '\u200F' // zero-width space/joiners, LRM, RLM
        || c is '\u2028' or '\u2029' // line and paragraph separators
        || c is >= '\u202A' and <= '\u202E' // bidi embeddings and overrides
        || c is >= '\u2060' and <= '\u2064' // word joiner and invisible operators
        || c is >= '\u2066' and <= '\u2069' // bidi isolates
        || c is '\uFEFF'; // zero-width no-break space

    private static string Replace(string value, bool keepNewlines)
    {
        var first = IndexOfUnsafe(value, keepNewlines);
        if (first < 0)
        {
            return value;
        }

        return string.Create(value.Length, (value, first, keepNewlines), static (span, state) =>
        {
            var (source, start, keep) = state;
            source.AsSpan(0, start).CopyTo(span);
            for (var i = start; i < source.Length; i++)
            {
                var c = source[i];
                span[i] = IsUnsafe(c) && !(keep && c == '\n') ? _replacement : c;
            }
        });
    }

    private static int IndexOfUnsafe(string value, bool keepNewlines)
    {
        for (var i = 0; i < value.Length; i++)
        {
            if (IsUnsafe(value[i]) && !(keepNewlines && value[i] == '\n'))
            {
                return i;
            }
        }

        return -1;
    }
}
