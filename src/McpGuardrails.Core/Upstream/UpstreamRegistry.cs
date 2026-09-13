using Microsoft.Extensions.Logging;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Upstream;

/// <summary>
/// Creates the transport used to reach one downstream server.
/// </summary>
/// <remarks>
/// A seam for testing. Production always spawns a child process over stdio, but
/// a test can substitute an in-memory stream pair and talk to a real MCP server
/// running in the same process - no npx, no network, no spawned binaries, and
/// tests that still exercise the genuine protocol rather than a mock.
/// </remarks>
public delegate IClientTransport UpstreamTransportFactory(
    UpstreamServerConfig config,
    ILoggerFactory loggerFactory);

/// <summary>
/// One live connection to a downstream MCP server, plus the tools it advertised.
/// </summary>
public sealed record UpstreamConnection(
    string Name,
    McpClient Client,
    IReadOnlyList<McpClientTool> Tools);

/// <summary>
/// Owns the connections to every downstream server and answers "which server
/// handles this tool?".
/// </summary>
/// <remarks>
/// This is the proxy's client half. The server half lives in the CLI's Program.cs.
///
/// C# notes:
///
/// - IAsyncDisposable is the async form of IDisposable, which is C#'s
///   deterministic cleanup contract (Java's try-with-resources / AutoCloseable).
///   Closing an MCP client means shutting down a child process and awaiting it,
///   which is I/O, hence the async variant.
///
/// - The connections are stored in a Dictionary built once at startup and never
///   mutated, so no locking is needed despite concurrent reads. Immutability is
///   the cheapest concurrency strategy available; reach for it before locks.
/// </remarks>
public sealed class UpstreamRegistry : IAsyncDisposable
{
    private readonly Dictionary<string, UpstreamConnection> _byServerName;

    // Maps the client-visible qualified name ("fs__read_file") straight to the
    // owning connection, the downstream name and the tool definition, so routing
    // a call is one dictionary lookup rather than a string split plus a second
    // lookup. The definition rides along because policy matches on the tool's
    // annotations, which only the downstream server knows.
    private readonly Dictionary<string, (UpstreamConnection Connection, McpClientTool Tool)> _byQualifiedName;

    private UpstreamRegistry(IReadOnlyList<UpstreamConnection> connections)
    {
        _byServerName = connections.ToDictionary(c => c.Name, StringComparer.Ordinal);

        _byQualifiedName = new Dictionary<string, (UpstreamConnection, McpClientTool)>(StringComparer.Ordinal);
        foreach (var connection in connections)
        {
            foreach (var tool in connection.Tools)
            {
                _byQualifiedName[ToolNamespacer.Qualify(connection.Name, tool.Name)] =
                    (connection, tool);
            }
        }
    }

    /// <summary>All downstream connections, in configuration order.</summary>
    public IReadOnlyCollection<UpstreamConnection> Connections => _byServerName.Values;

    /// <summary>
    /// Spawns and connects to every configured server, then caches its tool list.
    /// </summary>
    /// <remarks>
    /// Connections are established in parallel. Each one spawns a child process
    /// and waits for it to boot; doing that sequentially would make startup the
    /// sum of every server's boot time instead of the slowest one. Task.WhenAll
    /// is the idiomatic way to await a set of concurrent operations.
    /// </remarks>
    public static async Task<UpstreamRegistry> ConnectAsync(
        IReadOnlyList<UpstreamServerConfig> configs,
        ILoggerFactory loggerFactory,
        UpstreamTransportFactory? transportFactory = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configs);
        ArgumentNullException.ThrowIfNull(loggerFactory);

        transportFactory ??= CreateStdioTransport;

        foreach (var config in configs)
        {
            config.Validate();
        }

        var duplicate = configs
            .GroupBy(c => c.Name, StringComparer.Ordinal)
            .FirstOrDefault(g => g.Count() > 1);

        if (duplicate is not null)
        {
            throw new ArgumentException(
                $"Duplicate upstream server name '{duplicate.Key}'. Names must be unique.",
                nameof(configs));
        }

        var connections = await Task.WhenAll(
            configs.Select(c => ConnectOneAsync(c, loggerFactory, transportFactory, cancellationToken)));

        return new UpstreamRegistry(connections);
    }

    /// <summary>Production transport: spawn the server as a child process.</summary>
    /// <remarks>
    /// internal rather than private so tests can verify the config-to-transport
    /// mapping without spawning a process. Silently dropping EnvironmentVariables
    /// here would break real deployments in a way no other test would catch.
    /// </remarks>
    internal static IClientTransport CreateStdioTransport(
        UpstreamServerConfig config,
        ILoggerFactory loggerFactory) =>
        new StdioClientTransport(
            new StdioClientTransportOptions
            {
                Name = config.Name,
                Command = config.Command,
                Arguments = [.. config.Arguments],
                EnvironmentVariables = config.EnvironmentVariables?.ToDictionary(
                    kv => kv.Key, kv => kv.Value, StringComparer.Ordinal),
            },
            loggerFactory);

    private static async Task<UpstreamConnection> ConnectOneAsync(
        UpstreamServerConfig config,
        ILoggerFactory loggerFactory,
        UpstreamTransportFactory transportFactory,
        CancellationToken cancellationToken)
    {
        var transport = transportFactory(config, loggerFactory);

        var client = await McpClient.CreateAsync(
            transport,
            clientOptions: null,
            loggerFactory: loggerFactory,
            cancellationToken: cancellationToken);

        var tools = await client.ListToolsAsync(cancellationToken: cancellationToken);

        return new UpstreamConnection(config.Name, client, [.. tools]);
    }

    /// <summary>
    /// Resolves a client-visible tool name to the connection that serves it.
    /// </summary>
    /// <returns>False when no downstream server advertises that tool.</returns>
    public bool TryResolve(
        string qualifiedToolName,
        out UpstreamConnection connection,
        out string downstreamToolName)
    {
        if (_byQualifiedName.TryGetValue(qualifiedToolName, out var entry))
        {
            connection = entry.Connection;
            downstreamToolName = entry.Tool.Name;
            return true;
        }

        connection = null!;
        downstreamToolName = string.Empty;
        return false;
    }

    /// <summary>
    /// Looks up the downstream definition of a client-visible tool name.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="TryResolve"/> rather than a fourth out parameter:
    /// routing and policy want different things from the same entry, and a method
    /// with four outs reads worse than two with two. Both are one dictionary hit.
    /// </remarks>
    /// <returns>False when no downstream server advertises that tool.</returns>
    public bool TryGetTool(string qualifiedToolName, out Tool tool)
    {
        if (_byQualifiedName.TryGetValue(qualifiedToolName, out var entry))
        {
            // ProtocolTool, not the McpClientTool wrapper: the wrapper's Name can
            // disagree with the DTO's (see the note in ToolNamespacer), and policy
            // must see exactly what the client was told about.
            tool = entry.Tool.ProtocolTool;
            return true;
        }

        tool = null!;
        return false;
    }

    /// <summary>Shuts down every child process.</summary>
    public async ValueTask DisposeAsync()
    {
        foreach (var connection in _byServerName.Values)
        {
            // One misbehaving server must not prevent the others from closing,
            // so failures during shutdown are swallowed deliberately.
            try
            {
                await connection.Client.DisposeAsync();
            }
            catch (Exception)
            {
                // Intentionally ignored: we are already tearing down.
            }
        }
    }
}
