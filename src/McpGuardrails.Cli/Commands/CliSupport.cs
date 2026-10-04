using McpGuardrails.Core.Upstream;
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
        Environment.GetEnvironmentVariable(variable) ?? DefaultPath(fileName);

    /// <summary>The default location of one of the proxy's files.</summary>
    public static string DefaultPath(string fileName) =>
        Path.Combine(
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

/// <summary>The real machine, as the Core loaders see it.</summary>
internal static class CliHost
{
    public static HostEnvironment Environment { get; } = new()
    {
        GetVariable = System.Environment.GetEnvironmentVariable,
        VariableNames = () => System.Environment.GetEnvironmentVariables().Keys.Cast<string>(),
        FileExists = File.Exists,
        DirectoryExists = Directory.Exists,
        ReadAllText = File.ReadAllText,
        GetUnixFileMode = path => OperatingSystem.IsWindows() || !File.Exists(path) ? null : File.GetUnixFileMode(path),
        HomeDirectory = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile),
        IsWindows = OperatingSystem.IsWindows(),
        IsMacOS = OperatingSystem.IsMacOS(),
        UserAndGroup = ReadUserAndGroup,
    };

    /// <summary>The proxy's <c>uid:gid</c>, from <c>id</c>; null on Windows or when it cannot be read.</summary>
    /// <remarks>
    /// .NET has no API for the numeric user id, and a P/Invoke into libc would
    /// have to name a different library on each Unix. <c>id</c> is POSIX, and it
    /// only runs when a servers file isolates a server without naming a user.
    /// An absolute path, so a PATH entry cannot substitute its own.
    /// </remarks>
    private static string? ReadUserAndGroup()
    {
        if (OperatingSystem.IsWindows() || !File.Exists("/usr/bin/id"))
        {
            return null;
        }

        var user = RunId("-u");
        var group = RunId("-g");
        return user is null || group is null ? null : $"{user}:{group}";
    }

    private static string? RunId(string flag)
    {
        try
        {
            using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("/usr/bin/id", flag)
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
            });

            if (process is null)
            {
                return null;
            }

            var output = process.StandardOutput.ReadToEnd().Trim();
            process.WaitForExit();
            return process.ExitCode == 0 && output.Length > 0 && output.All(char.IsAsciiDigit) ? output : null;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }
}

/// <summary>Reads flags out of the command line.</summary>
internal static class CliArgs
{
    /// <summary>True when the bare flag is present.</summary>
    public static bool Has(string[] args, string flag) => args.Contains(flag, StringComparer.Ordinal);

    /// <summary>The value after <paramref name="flag"/>, or null when the flag is absent.</summary>
    /// <exception cref="CommandFailedException">The flag is the last argument, with no value after it.</exception>
    public static string? Value(string[] args, string flag)
    {
        var index = Array.IndexOf(args, flag);
        if (index < 0)
        {
            return null;
        }

        if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
        {
            throw new CommandFailedException(2, $"{flag} needs a value.");
        }

        return args[index + 1];
    }

    /// <summary>Every value given to a repeatable flag, in order.</summary>
    /// <exception cref="CommandFailedException">An occurrence of the flag has no value after it.</exception>
    public static IReadOnlyList<string> Values(string[] args, string flag)
    {
        var values = new List<string>();
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] != flag)
            {
                continue;
            }

            if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
            {
                throw new CommandFailedException(2, $"{flag} needs a value.");
            }

            values.Add(args[++i]);
        }

        return values;
    }

    /// <summary>The client named by <paramref name="flag"/>, which must be present.</summary>
    /// <exception cref="CommandFailedException">The flag is missing or names no supported client.</exception>
    public static ClientApp Client(string[] args, string flag)
    {
        var names = string.Join(", ", ClientConfigs.All.Select(c => c.Name));
        var name = Value(args, flag)
                   ?? throw new CommandFailedException(2, $"{flag} is required: one of {names}.");

        return ClientConfigs.Find(name)
               ?? throw new CommandFailedException(2, $"Unknown client '{name}'. Use one of {names}.");
    }
}

/// <summary>Finds a client's config file.</summary>
internal static class CliClientPaths
{
    /// <summary>
    /// The <c>--path</c> the user gave, else the first of the client's default
    /// locations that exists.
    /// </summary>
    /// <exception cref="CommandFailedException">Nothing was given and nothing exists.</exception>
    public static string Resolve(ClientApp client, string[] args)
    {
        if (CliArgs.Value(args, "--path") is { } explicitPath)
        {
            return File.Exists(explicitPath)
                ? Path.GetFullPath(explicitPath)
                : throw new CommandFailedException(1, $"Client config '{explicitPath}' does not exist.");
        }

        var candidates = ClientConfigs.DefaultPaths(client, CliHost.Environment, Directory.GetCurrentDirectory());

        return candidates.FirstOrDefault(File.Exists)
               ?? throw new CommandFailedException(
                   1,
                   candidates.Count == 0
                       ? $"{client.Name} has no default config location on this platform. Pass --path."
                       : $"No {client.Name} config found. Looked in:{System.Environment.NewLine}" +
                         string.Join(System.Environment.NewLine, candidates.Select(p => $"  {p}")) +
                         $"{System.Environment.NewLine}Pass --path to name it.");
    }
}

/// <summary>Where the servers file is, and whether one was asked for.</summary>
internal static class CliServers
{
    public const string DefaultFileName = "servers.yaml";

    /// <summary>
    /// The servers file named by <c>--servers</c> or <see cref="ServersLoader.FileVariable"/>,
    /// else the default path when a file exists there; null means "no servers
    /// file: use the built-in server", which an empty variable also asks for.
    /// </summary>
    /// <remarks>
    /// A file someone named explicitly and that is missing is an error, not a
    /// silent fallback to the built-in server - that would serve a different set
    /// of tools from the one they configured. Only the default location is
    /// allowed to be absent.
    /// </remarks>
    public static string? Path(string[] args)
    {
        if (CliArgs.Value(args, "--servers") is { } flag)
        {
            return flag;
        }

        // Set but empty is a deliberate "no servers file": the built-in server,
        // whatever sits at the default path. Tests use it to stay reproducible on
        // a machine with its own servers file, as they point the policy at a
        // file that does not exist.
        if (System.Environment.GetEnvironmentVariable(ServersLoader.FileVariable) is { } variable)
        {
            return string.IsNullOrWhiteSpace(variable) ? null : variable;
        }

        var fallback = CliPaths.DefaultPath(DefaultFileName);
        return File.Exists(fallback) ? fallback : null;
    }

    /// <summary>Prints the load result's warnings and errors in the format validate uses.</summary>
    public static void Report(ServersLoadResult result, TextWriter writer)
    {
        foreach (var warning in result.Warnings)
        {
            writer.WriteLine($"warning: {warning}");
        }

        foreach (var error in result.Errors)
        {
            writer.WriteLine($"error: {error}");
        }
    }
}
