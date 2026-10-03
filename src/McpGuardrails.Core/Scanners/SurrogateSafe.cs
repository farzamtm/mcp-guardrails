namespace McpGuardrails.Core.Scanners;

/// <summary>
/// Cuts that never split a UTF-16 surrogate pair.
/// </summary>
/// <remarks>
/// Half of a pair is not a character: a reader gets a replacement glyph, and the
/// JSON writer refuses to serialize it at all - which for the classifier request
/// would fail the call rather than shorten it. One place, so every cut the proxy
/// makes gets this right the same way.
/// </remarks>
internal static class SurrogateSafe
{
    /// <summary>
    /// The longest prefix no longer than <paramref name="length"/> that ends on a
    /// character boundary.
    /// </summary>
    /// <param name="text">The text being cut.</param>
    /// <param name="length">The most characters the prefix may have; at most the text's length.</param>
    public static int HeadLength(string text, int length) =>
        length > 0 && char.IsHighSurrogate(text[length - 1]) ? length - 1 : length;

    /// <summary>
    /// The first index at or after <paramref name="start"/> that begins a
    /// character, for a suffix that runs to the end of <paramref name="text"/>.
    /// </summary>
    /// <param name="text">The text being cut.</param>
    /// <param name="start">A valid index into <paramref name="text"/>.</param>
    public static int TailStart(string text, int start) =>
        char.IsLowSurrogate(text[start]) ? start + 1 : start;
}
