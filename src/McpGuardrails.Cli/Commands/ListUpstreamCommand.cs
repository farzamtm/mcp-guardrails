using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Cli.Commands;

/// <summary>
/// <c>list-upstream</c>: prints every tool the downstream servers advertise,
/// qualified as the client would see it, then exits.
/// </summary>
/// <remarks>
/// Stops after the shared startup - before the budget store is opened, so it
/// creates no database file (the example-policy check in CI runs exactly this),
/// and before the metadata findings are audited, so listing tools never adds
/// lines to the operator's log.
/// </remarks>
internal sealed class ListUpstreamCommand : ICliCommand
{
    public async Task<int> RunAsync(string[] args)
    {
        await using var startup = await ProxyStartup.LoadAsync(args, listing: true);

        foreach (var connection in startup.Upstream.Connections)
        {
            Console.WriteLine($"{connection.Name}  ({connection.Tools.Count} tools)");
            foreach (var tool in connection.Tools)
            {
                Console.WriteLine($"  {ToolNamespacer.Qualify(connection.Name, tool.Name),-40} {tool.Description?.ReplaceLineEndings(" ")}");
            }
        }

        return 0;
    }
}
