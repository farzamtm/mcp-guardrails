using McpGuardrails.Core.Text;
using McpGuardrails.Core.Upstream;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;

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
        logging.AddConsole(options =>
        {
            options.LogToStandardErrorThreshold = LogLevel.Trace;
            options.FormatterName = PrintableConsoleFormatter.FormatterName;
        });

        // Registered as a service rather than with AddConsoleFormatter, which
        // binds options by reflection that Native AOT cannot keep.
        logging.Services.AddSingleton<ConsoleFormatter, PrintableConsoleFormatter>();
        logging.SetMinimumLevel(listing ? LogLevel.Warning : LogLevel.Information);
    }
}

/// <summary>
/// The console log layout, with every message passed through
/// <see cref="TerminalText.PrintableLines"/>.
/// </summary>
/// <remarks>
/// Log lines quote downstream servers: the SDK logs a failed request with the
/// server's own error text. A hostile server could otherwise put an escape
/// sequence in the operator's terminal through the log, around every guard the
/// commands put on their own output. Same shape as the default "simple"
/// formatter - <c>warn: Category[id]</c>, then the message indented - minus the
/// colours, which are escape sequences too.
/// </remarks>
internal sealed class PrintableConsoleFormatter() : ConsoleFormatter(FormatterName)
{
    public const string FormatterName = "printable";

    private const string _indent = "      ";

    public override void Write<TState>(in LogEntry<TState> logEntry, IExternalScopeProvider? scopeProvider, TextWriter textWriter)
    {
        var message = logEntry.Formatter(logEntry.State, logEntry.Exception);
        if (message is null && logEntry.Exception is null)
        {
            return;
        }

        textWriter.Write(Level(logEntry.LogLevel));
        textWriter.Write(": ");
        textWriter.Write(logEntry.Category);
        textWriter.Write('[');
        textWriter.Write(logEntry.EventId.Id);
        textWriter.WriteLine(']');

        foreach (var text in new[] { message, logEntry.Exception?.ToString() })
        {
            if (!string.IsNullOrEmpty(text))
            {
                textWriter.Write(_indent);
                textWriter.WriteLine(TerminalText.PrintableLines(text).Replace("\n", Environment.NewLine + _indent, StringComparison.Ordinal));
            }
        }
    }

    private static string Level(LogLevel level) => level switch
    {
        LogLevel.Trace => "trce",
        LogLevel.Debug => "dbug",
        LogLevel.Information => "info",
        LogLevel.Warning => "warn",
        LogLevel.Error => "fail",
        LogLevel.Critical => "crit",
        _ => "none",
    };
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
    };
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
