namespace McpGuardrails.Core.Upstream;

/// <summary>The <c>env_file</c> format.</summary>
internal static class EnvFile
{
    /// <summary>
    /// Reads <c>KEY=VALUE</c> lines, as Docker and dotenv write them: blank lines
    /// and <c>#</c> comments are skipped, an <c>export </c> prefix is allowed, and
    /// one pair of matching quotes around the value is removed.
    /// </summary>
    /// <returns>The variables, or null with <paramref name="error"/> set; errors never echo a value.</returns>
    public static Dictionary<string, string?>? Parse(string text, out string? error)
    {
        error = null;
        var variables = new Dictionary<string, string?>(StringComparer.Ordinal);
        var lineNumber = 0;

        foreach (var rawLine in text.Split('\n'))
        {
            lineNumber++;
            var line = rawLine.TrimEnd('\r').Trim();

            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            if (line.StartsWith("export ", StringComparison.Ordinal))
            {
                line = line["export ".Length..].TrimStart();
            }

            var equals = line.IndexOf('=');
            var name = equals > 0 ? line[..equals].Trim() : string.Empty;

            if (!VariableExpander.IsValidName(name))
            {
                error = $"line {lineNumber} is not a KEY=VALUE pair";
                return null;
            }

            var value = line[(equals + 1)..].Trim();
            if (value.Length >= 2 && (value[0] is '"' or '\'') && value[^1] == value[0])
            {
                value = value[1..^1];
            }

            variables[name] = value;
        }

        return variables;
    }
}
