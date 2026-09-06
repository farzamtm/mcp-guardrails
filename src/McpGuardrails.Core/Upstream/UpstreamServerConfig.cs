using System.Text.RegularExpressions;

namespace McpGuardrails.Core.Upstream;

/// <summary>
/// Describes one downstream MCP server the proxy should front.
/// </summary>
/// <remarks>
/// C# notes:
///
/// - `record` generates a constructor, value equality, a readable ToString() and
///   `with`-expressions for you. Use records for data, classes for behaviour.
///
/// - `required` means the compiler refuses to let you construct this without
///   setting the property. It gives you constructor-style safety while keeping
///   the readable object-initializer syntax.
///
/// - `init` means the property can be set while constructing the object and never
///   again. Shallow immutability without writing a constructor by hand.
/// </remarks>
public sealed partial record UpstreamServerConfig
{
    /// <summary>
    /// Short identifier used to namespace this server's tools, e.g. "fs" produces
    /// tools called "fs__read_file".
    /// </summary>
    public required string Name { get; init; }

    /// <summary>Executable to spawn, e.g. "npx".</summary>
    public required string Command { get; init; }

    /// <summary>
    /// Arguments passed to <see cref="Command"/>.
    /// </summary>
    /// <remarks>
    /// Exposed as IReadOnlyList so callers cannot mutate our copy. `= []` is a
    /// collection expression - the modern way to write an empty collection.
    /// </remarks>
    public IReadOnlyList<string> Arguments { get; init; } = [];

    /// <summary>Extra environment variables for the child process.</summary>
    public IReadOnlyDictionary<string, string?>? EnvironmentVariables { get; init; }

    /// <summary>
    /// Server names must be letters, digits and hyphens only.
    /// </summary>
    /// <remarks>
    /// Underscores are deliberately excluded. Tool namespacing joins the server
    /// name and tool name with a double underscore ("fs" + "__" + "read_file").
    /// If a server name could itself contain "__", splitting the combined name
    /// back apart would be ambiguous. Forbidding it here makes the round trip
    /// provably reversible instead of merely usually correct.
    /// </remarks>
    [GeneratedRegex("^[a-zA-Z0-9-]+$")]
    private static partial Regex NamePattern { get; }

    /// <summary>
    /// Throws if this config is malformed. Call once at startup: a bad config
    /// should kill the process immediately, not produce a confusing failure later.
    /// </summary>
    public void Validate()
    {
        // ArgumentException.ThrowIfNullOrWhiteSpace is a "throw helper". The
        // [CallerArgumentExpression] attribute inside it captures the caller's
        // expression text, so the message names the offending property for free.
        ArgumentException.ThrowIfNullOrWhiteSpace(Name);
        ArgumentException.ThrowIfNullOrWhiteSpace(Command);

        if (!NamePattern.IsMatch(Name))
        {
            throw new ArgumentException(
                $"Upstream server name '{Name}' is invalid. " +
                "Use letters, digits and hyphens only (no underscores).",
                nameof(Name));
        }
    }
}
