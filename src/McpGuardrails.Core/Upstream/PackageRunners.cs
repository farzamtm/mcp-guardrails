namespace McpGuardrails.Core.Upstream;

/// <summary>
/// Spots servers launched through a package runner without a pinned version.
/// </summary>
/// <remarks>
/// <c>npx -y some-server</c> runs whatever the registry published most recently,
/// on every start. That is a supply-chain path into the one process meant to be
/// guarding the agent - the reason the built-in filesystem server is pinned (see
/// <see cref="DefaultUpstreams.FilesystemServerVersion"/>). Reported as a warning,
/// not an error: the most common config on the internet does exactly this, and
/// refusing it would stop people adopting the proxy at all.
/// </remarks>
public static class PackageRunners
{
    /// <summary>
    /// The unpinned package a command line would fetch, or null when it is pinned
    /// or not a package runner at all.
    /// </summary>
    public static string? FindUnpinned(string command, IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(arguments);

        var runner = Path.GetFileNameWithoutExtension(command.Replace('\\', '/').Split('/')[^1]);

        return runner switch
        {
            "npx" or "bunx" => Unpinned(FirstPackage(arguments, "--package", "-p"), IsPinnedNpm),
            "uvx" => Unpinned(FirstPackage(arguments, "--from", null), IsPinnedPython),
            _ => null,
        };
    }

    private static string? Unpinned(string? package, Func<string, bool> isPinned) =>
        package is not null && !isPinned(package) ? package : null;

    /// <summary>
    /// The package a runner will fetch: the value of its package option when one
    /// is given, else the first argument that is not an option.
    /// </summary>
    private static string? FirstPackage(IReadOnlyList<string> arguments, string longOption, string? shortOption)
    {
        for (var i = 0; i < arguments.Count; i++)
        {
            var argument = arguments[i];

            if (argument.StartsWith(longOption + "=", StringComparison.Ordinal))
            {
                return argument[(longOption.Length + 1)..];
            }

            if ((argument == longOption || argument == shortOption) && i + 1 < arguments.Count)
            {
                return arguments[i + 1];
            }

            if (!argument.StartsWith('-'))
            {
                return argument;
            }
        }

        return null;
    }

    /// <summary>
    /// <c>name@1.2.3</c> or <c>@scope/name@1.2.3</c>. A tag such as <c>@latest</c>
    /// or a range such as <c>@^1</c> moves, so it is not a pin.
    /// </summary>
    private static bool IsPinnedNpm(string package)
    {
        var at = package.LastIndexOf('@');
        return at > 0 && at + 1 < package.Length && char.IsAsciiDigit(package[at + 1]);
    }

    /// <summary><c>name==1.2.3</c> or <c>name@1.2.3</c>.</summary>
    private static bool IsPinnedPython(string package)
    {
        var separator = package.IndexOf("==", StringComparison.Ordinal);
        var length = 2;
        if (separator < 0)
        {
            separator = package.IndexOf('@');
            length = 1;
        }

        return separator > 0
               && separator + length < package.Length
               && char.IsAsciiDigit(package[separator + length]);
    }
}
