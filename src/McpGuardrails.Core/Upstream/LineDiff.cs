using System.Text;

namespace McpGuardrails.Core.Upstream;

/// <summary>
/// A minimal line diff, for <c>wrap --dry-run</c> to show what it would change.
/// </summary>
/// <remarks>
/// A longest-common-subsequence table: quadratic, which is nothing for a client
/// config of a few dozen lines, and it needs no dependency. Not meant for
/// arbitrary input; the CLI only ever feeds it a config file and its rewrite.
/// </remarks>
public static class LineDiff
{
    /// <summary>
    /// Every line of both texts, prefixed with <c>"  "</c> (in both),
    /// <c>"- "</c> (only in <paramref name="before"/>) or <c>"+ "</c> (only in
    /// <paramref name="after"/>).
    /// </summary>
    public static string Format(string before, string after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);

        var a = Lines(before);
        var b = Lines(after);

        // common[i, j] = length of the LCS of a[i..] and b[j..].
        var common = new int[a.Length + 1, b.Length + 1];
        for (var i = a.Length - 1; i >= 0; i--)
        {
            for (var j = b.Length - 1; j >= 0; j--)
            {
                common[i, j] = a[i] == b[j]
                    ? common[i + 1, j + 1] + 1
                    : Math.Max(common[i + 1, j], common[i, j + 1]);
            }
        }

        var output = new StringBuilder();
        int x = 0, y = 0;
        while (x < a.Length || y < b.Length)
        {
            if (x < a.Length && y < b.Length && a[x] == b[y])
            {
                output.Append("  ").Append(a[x++]).Append('\n');
                y++;
            }
            else if (y < b.Length && (x == a.Length || common[x, y + 1] > common[x + 1, y]))
            {
                output.Append("+ ").Append(b[y++]).Append('\n');
            }
            else
            {
                output.Append("- ").Append(a[x++]).Append('\n');
            }
        }

        return output.ToString();
    }

    private static string[] Lines(string text) =>
        text.Length == 0 ? [] : text.ReplaceLineEndings("\n").TrimEnd('\n').Split('\n');
}
