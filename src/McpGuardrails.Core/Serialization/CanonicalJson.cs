using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace McpGuardrails.Core.Serialization;

/// <summary>
/// One spelling for every JSON value that means the same thing, and a hash of it.
/// </summary>
/// <remarks>
/// Pinning a tool definition only works if the hash changes when the definition
/// does and stays put when it does not. A server that reorders the keys of its
/// input schema, re-indents it or writes <c>1.0</c> instead of <c>1</c> has not
/// changed the tool, and an alarm on every such upgrade would teach operators to
/// accept pin changes without reading them - which is the failure this exists to
/// prevent. So the hash is taken over a canonical form, close to RFC 8785 (JCS):
///
/// - object keys sorted by ordinal comparison of their UTF-16 code units;
/// - no insignificant whitespace;
/// - integers that fit in 64 bits written as integers, every other number in the
///   shortest form that round-trips through a double, so <c>1.0</c>, <c>1e0</c>
///   and <c>1</c> agree;
/// - strings exactly as received. Not Unicode-normalized: the shipped binary runs
///   with invariant globalization, where <see cref="string.Normalize()"/> is a
///   no-op, so normalizing would give the tests and the binary different hashes.
///   Comparing code points exactly is also the stricter choice - two strings that
///   look the same but differ underneath are different text to a model's tokenizer.
///
/// Linear in the size of the input, with recursion bounded by the parser's own
/// depth limit, because what is being canonicalized was written by a server the
/// proxy does not trust.
/// </remarks>
public static class CanonicalJson
{
    /// <summary>The prefix every hash carries, so the algorithm is in the value.</summary>
    public const string HashPrefix = "sha256:";

    // Relaxed escaping so the canonical text is readable when shown in a diff;
    // the choice does not affect equality, because the same writer produces every
    // canonical form that is compared.
    private static readonly JsonWriterOptions _writerOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Indented = false,
        SkipValidation = false,
    };

    private static readonly JsonWriterOptions _indentedOptions = _writerOptions with { Indented = true };

    /// <summary>The canonical text of <paramref name="value"/>.</summary>
    public static string Serialize(JsonElement value) => Write(value, _writerOptions);

    /// <summary>
    /// The canonical form laid out one value per line, for a person to diff.
    /// </summary>
    /// <remarks>Same key order and number forms as <see cref="Serialize"/>, so two
    /// definitions with the same hash always print the same.</remarks>
    public static string Format(JsonElement value) => Write(value, _indentedOptions);

    /// <summary>The SHA-256 of the canonical text, as <c>sha256:</c> and lowercase hex.</summary>
    public static string Hash(JsonElement value) => HashText(Serialize(value));

    /// <summary>The SHA-256 of already-canonical text, in the same format as <see cref="Hash(JsonElement)"/>.</summary>
    public static string HashText(string canonical)
    {
        ArgumentNullException.ThrowIfNull(canonical);

        return HashPrefix + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    /// <summary>True when <paramref name="value"/> is shaped like a hash this class produces.</summary>
    public static bool IsHash(string? value) =>
        value is { Length: 71 } &&
        value.StartsWith(HashPrefix, StringComparison.Ordinal) &&
        value.AsSpan(HashPrefix.Length).IndexOfAnyExcept("0123456789abcdef") < 0;

    private static string Write(JsonElement value, JsonWriterOptions options)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, options))
        {
            WriteValue(writer, value);
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static void WriteValue(Utf8JsonWriter writer, JsonElement value)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();

                var members = value.EnumerateObject().ToList();
                members.Sort(CompareMembers);

                foreach (var member in members)
                {
                    writer.WritePropertyName(member.Name);
                    WriteValue(writer, member.Value);
                }

                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in value.EnumerateArray())
                {
                    WriteValue(writer, item);
                }

                writer.WriteEndArray();
                break;

            case JsonValueKind.String:
                writer.WriteStringValue(value.GetString());
                break;

            case JsonValueKind.Number:
                writer.WriteRawValue(Number(value), skipInputValidation: true);
                break;

            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                break;

            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                break;

            default:
                // Null, and Undefined - a default JsonElement, which is what an
                // absent schema looks like - both mean "nothing here".
                writer.WriteNullValue();
                break;
        }
    }

    /// <summary>Orders object members by name, and duplicated names by value.</summary>
    /// <remarks>
    /// A schema with a duplicated key is legal to parse and meaningless to send,
    /// but it still needs exactly one canonical form. The values are only
    /// serialized to break a tie, so the ordinary case stays linear rather than
    /// re-serializing every subtree once per ancestor.
    /// </remarks>
    private static int CompareMembers(JsonProperty x, JsonProperty y)
    {
        var byName = string.CompareOrdinal(x.Name, y.Name);
        return byName != 0
            ? byName
            : string.CompareOrdinal(Serialize(x.Value), Serialize(y.Value));
    }

    /// <summary>The canonical spelling of one JSON number.</summary>
    private static string Number(JsonElement value)
    {
        if (value.TryGetInt64(out var integer))
        {
            return integer.ToString(CultureInfo.InvariantCulture);
        }

        // Every JSON number parses as a double; one too large for it (1e400)
        // parses as infinity, which has no JSON spelling.
        var real = value.GetDouble();
        if (double.IsFinite(real))
        {
            // -0.0 and 0.0 are the same number to every JSON consumer that matters.
            return real == 0
                ? "0"
                : real.ToString("R", CultureInfo.InvariantCulture);
        }

        // Too large for a double (1e400): there is no shorter equivalent to find,
        // and the raw text is at least deterministic.
        return value.GetRawText();
    }
}
