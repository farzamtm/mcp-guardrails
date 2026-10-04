namespace McpGuardrails.Cli.Commands;

/// <summary>One subcommand of the CLI.</summary>
internal interface ICliCommand
{
    /// <summary>Runs the command and returns the process exit code.</summary>
    /// <param name="args">The full command line, flags included.</param>
    Task<int> RunAsync(string[] args);
}

/// <summary>
/// A command failed before it could do its work. The message is printed to
/// stderr and the process exits with <see cref="ExitCode"/>.
/// </summary>
/// <remarks>
/// Thrown rather than returned so the shared startup can bail out from deep
/// inside without every caller threading an exit code back up.
/// </remarks>
internal sealed class CommandFailedException(int exitCode, string message) : Exception(message)
{
    /// <summary>1 for a bad file or unavailable resource, 2 for a bad command line.</summary>
    public int ExitCode { get; } = exitCode;
}

/// <summary>Maps the command line to the command that handles it.</summary>
internal static class CommandTable
{
    // A plain argument scan rather than a command-line parser: a handful of
    // flags and subcommands do not justify a dependency. A subcommand is found
    // anywhere on the command line, not only first, as it always has been, so
    // existing launcher configs keep working whatever order they use.
    private static readonly (string Name, Func<ICliCommand> Create)[] _commands =
    [
        ("list-upstream", () => new ListUpstreamCommand()),
        ("validate", () => new ValidateCommand()),
        ("import", () => new ImportCommand()),
        ("wrap", () => new WrapCommand()),
        ("unwrap", () => new UnwrapCommand()),
    ];

    /// <summary>Runs the named subcommand, or serves when none is named.</summary>
    public static async Task<int> RunAsync(string[] args)
    {
        var command = _commands
            .Where(entry => args.Contains(entry.Name, StringComparer.Ordinal))
            .Select(entry => entry.Create())
            .FirstOrDefault() ?? new ServeCommand();

        try
        {
            return await command.RunAsync(args);
        }
        catch (CommandFailedException ex)
        {
            // Console.Error, not stdout: stdout is the JSON-RPC wire.
            await Console.Error.WriteLineAsync(ex.Message);
            return ex.ExitCode;
        }
    }
}
