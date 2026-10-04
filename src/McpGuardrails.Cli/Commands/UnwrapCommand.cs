using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Cli.Commands;

/// <summary>
/// <c>unwrap --client &lt;client&gt;</c>: puts back the client config <c>wrap</c>
/// replaced, byte for byte.
/// </summary>
/// <remarks>
/// Refuses when the config changed after it was wrapped, unless <c>--force</c>,
/// because restoring the backup would throw that change away. The servers file
/// wrap wrote is left alone: it is configuration someone may have edited since.
/// </remarks>
internal sealed class UnwrapCommand : ICliCommand
{
    public Task<int> RunAsync(string[] args)
    {
        var client = CliArgs.Client(args, "--client");
        var configPath = CliClientPaths.Resolve(client, args);

        try
        {
            var backup = ClientConfigFiles.Restore(configPath, CliArgs.Has(args, "--force"));
            Console.WriteLine($"Restored {configPath} from {backup}. Restart {client.Name} to use it.");
            return Task.FromResult(0);
        }
        catch (ClientConfigException ex)
        {
            throw new CommandFailedException(1, ex.Message);
        }
    }
}
