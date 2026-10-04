namespace McpGuardrails.Core.Upstream;

/// <summary>Finds the program a stdio server's <c>command</c> names.</summary>
internal static class CommandLocator
{
    /// <summary>
    /// Whether <paramref name="command"/> names something the child could run:
    /// an absolute path that exists, or a bare name found on PATH.
    /// </summary>
    /// <remarks>
    /// Checked at load time so a typo fails before anything is spawned, with a
    /// message naming the server - rather than as a connection error from the SDK
    /// once the proxy is half started.
    /// </remarks>
    public static string? Check(string command, HostEnvironment host)
    {
        if (Path.IsPathFullyQualified(command))
        {
            return host.FileExists(command) ? null : "does not exist";
        }

        if (command.Contains('/') || command.Contains('\\'))
        {
            return "is a relative path. Use an absolute path, or a command name found on PATH";
        }

        var separator = host.IsWindows ? ';' : ':';
        var extensions = host.IsWindows
            ? ["", .. (host.GetVariable("PATHEXT") ?? ".COM;.EXE;.BAT;.CMD").Split(';', StringSplitOptions.RemoveEmptyEntries)]
            : new[] { "" };

        foreach (var directory in (host.GetVariable("PATH") ?? string.Empty).Split(separator, StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var extension in extensions)
            {
                if (host.FileExists(Path.Combine(directory, command + extension)))
                {
                    return null;
                }
            }
        }

        return "was not found on PATH";
    }
}
