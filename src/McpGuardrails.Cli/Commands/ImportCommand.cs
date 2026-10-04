using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Cli.Commands;

/// <summary>
/// <c>import --from &lt;client&gt;</c>: turns a client's MCP server list into a
/// servers file.
/// </summary>
/// <remarks>
/// Writes to <c>-o &lt;path&gt;</c>, or to stdout. Secrets found in the config are
/// never written: the servers file gets <c>${VAR}</c> references, and the values
/// are printed once to stderr for the user to put in the proxy's environment.
/// </remarks>
internal sealed class ImportCommand : ICliCommand
{
    public async Task<int> RunAsync(string[] args)
    {
        var client = CliArgs.Client(args, "--from");
        var configPath = CliClientPaths.Resolve(client, args);
        var output = CliArgs.Value(args, "-o");

        ImportResult result;
        try
        {
            result = ClientConfigs.Import(client, await File.ReadAllTextAsync(configPath), configPath, CliHost.Environment);
        }
        catch (ClientConfigException ex)
        {
            throw new CommandFailedException(1, ex.Message);
        }

        if (output is null)
        {
            Console.Write(result.ServersYaml);
        }
        else
        {
            // Never over an existing file: it may be a servers file someone
            // already edited by hand.
            try
            {
                await using var stream = new FileStream(output, FileMode.CreateNew, FileAccess.Write);
                await using var writer = new StreamWriter(stream);
                await writer.WriteAsync(result.ServersYaml);
            }
            catch (IOException) when (File.Exists(output))
            {
                throw new CommandFailedException(1, $"'{output}' already exists. Choose another path or remove it first.");
            }

            await Console.Error.WriteLineAsync($"Wrote {result.ServerCount} server(s) from {configPath} to {output}.");
        }

        await WriteNotesAsync(result);
        return 0;
    }

    /// <summary>Renames, dropped keys and lifted secrets, on stderr so stdout stays the file.</summary>
    internal static async Task WriteNotesAsync(ImportResult result)
    {
        foreach (var note in result.Notes)
        {
            await Console.Error.WriteLineAsync($"note: {note}");
        }

        if (result.Secrets.Count == 0)
        {
            return;
        }

        await Console.Error.WriteLineAsync(
            "These values looked like secrets, so the servers file references them as variables instead. " +
            "They are shown once here and were not written anywhere; set them in the proxy's environment:");
        foreach (var secret in result.Secrets)
        {
            await Console.Error.WriteLineAsync($"  {secret.Variable}={secret.Value}    # {secret.Server} {secret.Field}");
        }
    }
}
