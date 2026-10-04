using System.Globalization;
using System.Text.Json;

namespace McpGuardrails.Core.Upstream;

/// <summary>Durations as the servers file writes them.</summary>
internal static class Durations
{
    /// <summary>
    /// Parses a duration: a number of seconds, or a number followed by
    /// <c>ms</c>, <c>s</c> or <c>m</c>.
    /// </summary>
    public static bool TryParse(JsonElement element, out TimeSpan duration)
    {
        duration = default;

        if (element.ValueKind is JsonValueKind.Number)
        {
            var seconds = element.GetDouble();
            if (seconds < 0)
            {
                return false;
            }

            duration = TimeSpan.FromSeconds(seconds);
            return true;
        }

        if (element.ValueKind is not JsonValueKind.String)
        {
            return false;
        }

        var text = element.GetString()!;
        var (number, scale) = text switch
        {
            _ when text.EndsWith("ms", StringComparison.Ordinal) => (text[..^2], 0.001),
            _ when text.EndsWith('s') => (text[..^1], 1.0),
            _ when text.EndsWith('m') => (text[..^1], 60.0),
            _ => (text, 1.0),
        };

        if (!double.TryParse(number, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var value))
        {
            return false;
        }

        duration = TimeSpan.FromSeconds(value * scale);
        return true;
    }
}
