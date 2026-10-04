using System.Text;

namespace McpGuardrails.Core.Upstream;

/// <summary>
/// The result of expanding one templated value from the servers file.
/// </summary>
/// <param name="Value">The expanded text, or null when expansion failed.</param>
/// <param name="Error">
/// Why expansion failed, naming the variable but never a value; null on success.
/// </param>
public sealed record Expansion(string? Value, string? Error)
{
    /// <summary>True when every reference resolved.</summary>
    public bool Succeeded => Error is null;
}

/// <summary>
/// Expands <c>${VAR}</c> references in values from the servers file.
/// </summary>
/// <remarks>
/// Supported forms, chosen to read the configs users already have:
///
/// - <c>${VAR}</c> and <c>${VAR:-default}</c>, as Claude Code writes them. The
///   default applies when the variable is unset or empty, as in a POSIX shell.
/// - <c>${env:VAR}</c> (and <c>${env:VAR:-default}</c>), as Cursor and VS Code
///   write them. An alias, not a different lookup.
/// - <c>$$</c> for a literal <c>$</c>. A lone <c>$</c> not followed by <c>{</c>
///   is left alone, so <c>price$5</c> needs no escaping.
///
/// <b>An unset variable with no default is an error.</b> Claude Code leaves the
/// literal <c>${VAR}</c> in place, which turns a missing token into a request
/// with "Bearer ${TOKEN}" in it, or a server launched against a path that does
/// not exist. A proxy that is meant to fail closed refuses to start instead.
///
/// <c>${input:...}</c> (VS Code's prompted inputs) is refused with an
/// explanation: there is no UI here to prompt from.
///
/// A hand-written single pass rather than a regex: values are user configuration
/// and each character is visited once, so no input can make it slow, and a
/// nested or unterminated reference produces an error that says what is wrong.
/// </remarks>
public static class VariableExpander
{
    /// <summary>Expands every reference in <paramref name="template"/>.</summary>
    /// <param name="template">The value as written in the file.</param>
    /// <param name="lookup">Reads an environment variable; null means unset.</param>
    public static Expansion Expand(string template, Func<string, string?> lookup)
    {
        ArgumentNullException.ThrowIfNull(template);
        ArgumentNullException.ThrowIfNull(lookup);

        // The common case - a value with no '$' at all - costs one scan and no
        // allocation.
        if (!template.Contains('$', StringComparison.Ordinal))
        {
            return new Expansion(template, null);
        }

        var result = new StringBuilder(template.Length);
        var i = 0;

        while (i < template.Length)
        {
            var c = template[i];

            if (c != '$' || i + 1 == template.Length)
            {
                result.Append(c);
                i++;
                continue;
            }

            var next = template[i + 1];

            if (next == '$')
            {
                result.Append('$');
                i += 2;
                continue;
            }

            if (next != '{')
            {
                result.Append('$');
                i++;
                continue;
            }

            var close = template.IndexOf('}', i + 2);
            if (close < 0)
            {
                return Failed($"has an unterminated '${{' at position {i}. Close it with '}}', or write '$$' for a literal '$'.");
            }

            var body = template.AsSpan(i + 2, close - i - 2);

            // "${A:-${B}}" would need a second level of parsing, and every
            // client that supports defaults disagrees about what it means.
            // Refused rather than read as the literal default "${B".
            if (body.Contains("${", StringComparison.Ordinal))
            {
                return Failed($"has a nested '${{' inside '${{{body}}}'. Nested references are not supported.");
            }

            var resolved = Resolve(body, lookup, out var error);
            if (error is not null)
            {
                return Failed(error);
            }

            result.Append(resolved);
            i = close + 1;
        }

        return new Expansion(result.ToString(), null);
    }

    private static string? Resolve(ReadOnlySpan<char> body, Func<string, string?> lookup, out string? error)
    {
        error = null;

        if (body.StartsWith("input:", StringComparison.Ordinal))
        {
            error = $"uses '${{{body}}}', a VS Code prompted input. The proxy has no UI to prompt " +
                    "from; put the value in an environment variable and reference it as '${NAME}'.";
            return null;
        }

        if (body.StartsWith("env:", StringComparison.Ordinal))
        {
            body = body["env:".Length..];
        }

        ReadOnlySpan<char> name = body;
        string? fallback = null;

        var separator = body.IndexOf(":-", StringComparison.Ordinal);
        if (separator >= 0)
        {
            name = body[..separator];
            fallback = body[(separator + 2)..].ToString();
        }

        if (!IsValidName(name))
        {
            error = $"references '${{{body}}}', which is not a variable name. Use letters, digits " +
                    "and underscores, not starting with a digit.";
            return null;
        }

        var nameText = name.ToString();
        var value = lookup(nameText);

        if (string.IsNullOrEmpty(value) && fallback is not null)
        {
            return fallback;
        }

        if (value is null)
        {
            error = $"references '${{{nameText}}}', which is not set. Set it in the proxy's " +
                    $"environment, or give a default with '${{{nameText}:-value}}'.";
            return null;
        }

        return value;
    }

    /// <summary>A POSIX environment variable name: <c>[A-Za-z_][A-Za-z0-9_]*</c>.</summary>
    internal static bool IsValidName(ReadOnlySpan<char> name)
    {
        if (name.IsEmpty || char.IsAsciiDigit(name[0]))
        {
            return false;
        }

        foreach (var c in name)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c != '_')
            {
                return false;
            }
        }

        return true;
    }

    private static Expansion Failed(string error) => new(null, error);
}
