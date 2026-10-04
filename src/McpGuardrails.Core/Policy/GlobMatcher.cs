namespace McpGuardrails.Core.Policy;

/// <summary>
/// Matches a tool name against a shell-style glob: <c>*</c> for any run of
/// characters, <c>?</c> for exactly one.
/// </summary>
/// <remarks>
/// Hand-rolled rather than translated into a <see cref="System.Text.RegularExpressions.Regex"/>,
/// for three reasons:
///
/// - <b>No catastrophic backtracking.</b> Policy files are configuration, and a
///   regex built from configuration is a denial-of-service vector. This matcher
///   is O(pattern x input) worst case with a single backtrack point, so no
///   pattern can make it hang.
/// - <b>No escaping bugs.</b> Translating a glob to a regex means escaping every
///   other metacharacter correctly; a tool name containing <c>.</c> or <c>+</c>
///   would otherwise match things it should not.
/// - <b>No allocation.</b> Matching runs on every rule of every tool call. This
///   walks two spans and allocates nothing.
///
/// Matching is ordinal and case-sensitive by default, like the rest of
/// tool-name handling: MCP tool names are identifiers, not prose, and
/// <c>FS__Write_File</c> is simply a different tool from <c>fs__write_file</c>.
/// Callers matching names that are not identifiers - principals, which are
/// often email addresses an identity provider spells in whatever case the
/// account was created with - ask for case-insensitive matching instead.
/// </remarks>
public static class GlobMatcher
{
    /// <summary>True when <paramref name="value"/> matches <paramref name="pattern"/>.</summary>
    /// <param name="pattern">The glob.</param>
    /// <param name="value">The name to test.</param>
    /// <param name="ignoreCase">
    /// Compare characters the way <see cref="StringComparison.OrdinalIgnoreCase"/>
    /// does, rather than exactly.
    /// </param>
    /// <remarks>
    /// The algorithm is the classic two-pointer glob match. When a <c>*</c> is
    /// met, remember where it was and assume it consumes nothing; on a later
    /// mismatch, rewind and let it consume one more character. That collapses
    /// what looks like exponential search into a linear scan, because only the
    /// most recent <c>*</c> ever needs to grow.
    /// </remarks>
    public static bool IsMatch(ReadOnlySpan<char> pattern, ReadOnlySpan<char> value, bool ignoreCase = false)
    {
        int patternIndex = 0;
        int valueIndex = 0;

        // -1 means "no star seen yet", so a mismatch is final rather than a
        // rewind to a star that does not exist.
        int starIndex = -1;
        int rewindIndex = 0;

        while (valueIndex < value.Length)
        {
            if (patternIndex < pattern.Length &&
                (pattern[patternIndex] == '?' || Same(pattern[patternIndex], value[valueIndex], ignoreCase)))
            {
                patternIndex++;
                valueIndex++;
            }
            else if (patternIndex < pattern.Length && pattern[patternIndex] == '*')
            {
                // Provisionally match zero characters, and record where to come
                // back to if that turns out to be too few.
                starIndex = patternIndex;
                rewindIndex = valueIndex;
                patternIndex++;
            }
            else if (starIndex != -1)
            {
                // Mismatch, but an earlier '*' can absorb one more character.
                patternIndex = starIndex + 1;
                rewindIndex++;
                valueIndex = rewindIndex;
            }
            else
            {
                return false;
            }
        }

        // Trailing stars may still match the empty remainder; anything else left
        // in the pattern means the value ran out too early.
        while (patternIndex < pattern.Length && pattern[patternIndex] == '*')
        {
            patternIndex++;
        }

        return patternIndex == pattern.Length;
    }

    /// <remarks>
    /// Per-character invariant upper-casing is what
    /// <see cref="StringComparison.OrdinalIgnoreCase"/> does, without allocating
    /// or depending on the culture.
    /// </remarks>
    private static bool Same(char pattern, char value, bool ignoreCase) =>
        pattern == value || (ignoreCase && char.ToUpperInvariant(pattern) == char.ToUpperInvariant(value));
}
