using Microsoft.Extensions.Logging;

namespace McpGuardrails.Cli.Commands;

/// <summary>Where the proxy's files live.</summary>
internal static class CliPaths
{
    /// <summary>
    /// The deployment's choice of file, else a stable default under the home
    /// directory.
    /// </summary>
    /// <remarks>
    /// Stable matters: launched from Claude Desktop the process has no cwd you
    /// can predict, so a relative default would scatter files wherever the
    /// client happened to start us.
    /// </remarks>
    public static string ConfigPath(string variable, string fileName) =>
        Environment.GetEnvironmentVariable(variable)
        ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".mcp-guardrails",
            fileName);
}

/// <summary>Logging set up the same way for every command.</summary>
internal static class CliLogging
{
    /// <summary>Sends every log line to stderr.</summary>
    /// <remarks>
    /// CRITICAL for stdio servers: stdout is the JSON-RPC wire. Any log line
    /// landing there is interleaved with protocol frames and the client's JSON
    /// parser dies on it. This is the single most common way to break an stdio
    /// MCP server.
    /// </remarks>
    /// <param name="logging">The builder to configure.</param>
    /// <param name="listing">
    /// True for list-upstream, which prints its listing to stdout and wants only
    /// warnings beside it.
    /// </param>
    public static void ToStandardError(ILoggingBuilder logging, bool listing)
    {
        logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);
        logging.SetMinimumLevel(listing ? LogLevel.Warning : LogLevel.Information);
    }
}
