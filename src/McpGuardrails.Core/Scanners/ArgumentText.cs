using System.Buffers;
using System.Text;

namespace McpGuardrails.Core.Scanners;

/// <summary>
/// The text rules the argument detectors share: what a separator is, where a
/// word ends, and how escapes and look-alike characters decode.
/// </summary>
/// <remarks>
/// One place, because these rules decide how lenient the detectors are, and a
/// detector that decodes less than its neighbour is the one an attacker aims
/// at. Whatever a server or HTTP client would undo before acting on a value is
/// undone here too, so the detectors judge what the downstream sees rather than
/// what was typed.
///
/// Every function is linear in its input. <see cref="string.Normalize()"/> is
/// not used: the proxy runs with invariant globalization, where it does nothing,
/// so the foldings below are written out by hand.
/// </remarks>
internal static class ArgumentText
{
    // Enough for an encoding nested three deep (%25252e), which is past what
    // any server decodes; a fixed bound keeps decoding linear.
    private const int _maxDecodePasses = 3;

    /// <summary>
    /// Every character <see cref="char.IsWhiteSpace(char)"/> accepts, so the
    /// "is this prose?" test and the word split agree on what a space is.
    /// </summary>
    private static readonly SearchValues<char> _whitespace = SearchValues.Create(
        [.. Enumerable.Range(0, char.MaxValue + 1).Select(c => (char)c).Where(char.IsWhiteSpace)]);

    /// <summary>
    /// True for a path separator, including the Unicode look-alikes that some
    /// path and URL normalisers fold into one.
    /// </summary>
    public static bool IsSeparator(char c) => c is '/' or '\\' or '∕' or '⁄' or '／' or '＼' or '⧵';

    /// <summary>True when the value contains any whitespace character.</summary>
    public static bool HasWhitespace(ReadOnlySpan<char> value) => value.ContainsAny(_whitespace);

    /// <summary>True for a character that ends a word in prose: whitespace or a quote.</summary>
    public static bool IsWordBreak(char c) => char.IsWhiteSpace(c) || c is '"' or '\'' or '`';

    /// <summary>
    /// True for the characters the URL standard and Python's <c>urlsplit</c>
    /// delete from a URL before parsing it, wherever they appear.
    /// </summary>
    public static bool IsStrippedFromUrls(char c) => c is '\t' or '\n' or '\r';

    /// <summary>
    /// Decodes <c>%XX</c>, <c>%uXXXX</c>, UTF-8 sequences and the overlong UTF-8
    /// forms lenient decoders accept, repeatedly, so a double-encoded
    /// <c>%252e</c> becomes a dot just as <c>%2e</c> does.
    /// </summary>
    /// <returns>The value itself when it has no escape to decode.</returns>
    public static string Decode(string value)
    {
        for (var pass = 0; pass < _maxDecodePasses && value.Contains('%'); pass++)
        {
            var decoded = DecodeOnce(value);
            if (ReferenceEquals(decoded, value))
            {
                break;
            }

            value = decoded;
        }

        return value;
    }

    private static string DecodeOnce(string value)
    {
        var builder = new StringBuilder(value.Length);
        var changed = false;
        Span<byte> bytes = stackalloc byte[4];

        var i = 0;
        while (i < value.Length)
        {
            if (value[i] != '%')
            {
                builder.Append(value[i++]);
                continue;
            }

            if (TryUnicodeEscape(value, i, out var unit))
            {
                builder.Append(unit);
                i += 6;
                changed = true;
                continue;
            }

            // A run of %XX bytes, read up to one UTF-8 sequence long.
            var count = 0;
            while (count < 4 && TryHexByte(value, i + (3 * count), out bytes[count]))
            {
                count++;
            }

            if (count == 0)
            {
                builder.Append(value[i++]);
                continue;
            }

            var (text, used) = DecodeBytes(bytes[..count]);
            if (used == 0)
            {
                // Not a character in any form: keep the escape as written.
                builder.Append(value, i, 3);
                i += 3;
                continue;
            }

            builder.Append(text);
            i += 3 * used;
            changed = true;
        }

        return changed ? builder.ToString() : value;
    }

    /// <summary>The first character the bytes encode, and how many bytes it took; zero when none.</summary>
    private static (string Text, int Used) DecodeBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes[0] < 0x80)
        {
            return (((char)bytes[0]).ToString(), 1);
        }

        // Overlong encodings of '.', '/' and '\': invalid UTF-8, which is why
        // strict decoders refuse them and lenient ones have been fooled by them.
        if (bytes.Length >= 2 && bytes[0] is 0xC0 or 0xC1)
        {
            return (bytes[0], bytes[1]) switch
            {
                (0xC0, 0xAE) => (".", 2),
                (0xC0, 0xAF) => ("/", 2),
                (0xC1, 0x9C) => ("\\", 2),
                _ => ("", 0),
            };
        }

        if (bytes.Length >= 3 && bytes[0] == 0xE0 && bytes[1] == 0x80)
        {
            switch (bytes[2])
            {
                case 0xAE:
                    return (".", 3);
                case 0xAF:
                    return ("/", 3);
            }
        }

        return Rune.DecodeFromUtf8(bytes, out var rune, out var used) is OperationStatus.Done
            ? (rune.ToString(), used)
            : ("", 0);
    }

    private static bool TryHexByte(string value, int index, out byte decoded)
    {
        decoded = 0;

        if (index + 2 >= value.Length ||
            value[index] != '%' || !char.IsAsciiHexDigit(value[index + 1]) || !char.IsAsciiHexDigit(value[index + 2]))
        {
            return false;
        }

        decoded = (byte)((HexValue(value[index + 1]) << 4) | HexValue(value[index + 2]));
        return true;
    }

    /// <summary>IIS-style <c>%uXXXX</c>.</summary>
    private static bool TryUnicodeEscape(string value, int index, out char unit)
    {
        unit = '\0';

        if (index + 5 >= value.Length || value[index + 1] is not ('u' or 'U'))
        {
            return false;
        }

        var code = 0;
        for (var j = index + 2; j < index + 6; j++)
        {
            if (!char.IsAsciiHexDigit(value[j]))
            {
                return false;
            }

            code = (code << 4) | HexValue(value[j]);
        }

        unit = (char)code;
        return true;
    }

    private static int HexValue(char c) => char.IsAsciiDigit(c) ? c - '0' : (char.ToLowerInvariant(c) - 'a') + 10;

    /// <summary>
    /// Folds the compatibility forms that IDNA maps to ASCII in a host name -
    /// full-width letters and digits, circled and other enclosed digits,
    /// super- and subscripts, mathematical digits, ideographic dots - so
    /// <c>１２７．０．０．１</c> and <c>①②⑦.⓪.⓪.①</c> are read as the
    /// <c>127.0.0.1</c> a URL parser turns them into.
    /// </summary>
    /// <returns>The host itself when it is all ASCII.</returns>
    public static string FoldHost(string host)
    {
        if (Ascii.IsValid(host))
        {
            return host;
        }

        var builder = new StringBuilder(host.Length);

        for (var i = 0; i < host.Length; i++)
        {
            if (char.IsHighSurrogate(host[i]) && i + 1 < host.Length && char.IsLowSurrogate(host[i + 1]))
            {
                var code = char.ConvertToUtf32(host[i], host[i + 1]);
                i++;

                // Mathematical bold, double-struck, sans-serif and monospace
                // digits: five runs of ten.
                if (code is >= 0x1D7CE and <= 0x1D7FF)
                {
                    builder.Append((char)('0' + ((code - 0x1D7CE) % 10)));
                }
                else
                {
                    builder.Append(char.ConvertFromUtf32(code));
                }

                continue;
            }

            builder.Append(Fold(host[i]));
        }

        return builder.ToString();
    }

    private static string Fold(char c) => c switch
    {
        >= '！' and <= '～' => ((char)(c - 0xFEE0)).ToString(),
        '。' or '｡' or '․' or '﹒' => ".",
        >= '①' and <= '⑳' => (c - '①' + 1).ToString(System.Globalization.CultureInfo.InvariantCulture),
        >= '⒈' and <= '⒛' => (c - '⒈' + 1).ToString(System.Globalization.CultureInfo.InvariantCulture) + ".",
        '⓪' or '⓿' => "0",
        >= '⓫' and <= '⓴' => (c - '⓫' + 11).ToString(System.Globalization.CultureInfo.InvariantCulture),
        >= '⓵' and <= '⓾' => (c - '⓵' + 1).ToString(System.Globalization.CultureInfo.InvariantCulture),
        >= '❶' and <= '❿' => (c - '❶' + 1).ToString(System.Globalization.CultureInfo.InvariantCulture),
        >= '➀' and <= '➉' => (c - '➀' + 1).ToString(System.Globalization.CultureInfo.InvariantCulture),
        >= '➊' and <= '➓' => (c - '➊' + 1).ToString(System.Globalization.CultureInfo.InvariantCulture),
        >= 'Ⓐ' and <= 'Ⓩ' => ((char)('a' + (c - 'Ⓐ'))).ToString(),
        >= 'ⓐ' and <= 'ⓩ' => ((char)('a' + (c - 'ⓐ'))).ToString(),
        '¹' => "1",
        '²' => "2",
        '³' => "3",
        '⁰' => "0",
        >= '⁴' and <= '⁹' => ((char)('4' + (c - '⁴'))).ToString(),
        >= '₀' and <= '₉' => ((char)('0' + (c - '₀'))).ToString(),
        _ => c.ToString(),
    };
}
