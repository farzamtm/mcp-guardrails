using System.IO.Pipelines;
using McpGuardrails.Core.Upstream;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace McpGuardrails.Core.Tests.Upstream;

/// <summary>
/// A genuine MCP server running in the test process, reachable over an in-memory
/// stream pair instead of a spawned child process.
/// </summary>
/// <remarks>
/// Why this instead of a mock:
///
/// Mocking IMcpClient would test that UpstreamRegistry calls the methods we think
/// it calls. This tests that it actually speaks MCP correctly - real JSON-RPC
/// frames, real tool schemas, real serialization - while staying fast and
/// hermetic. No npx, no network, no processes to leak.
///
/// The wiring is two pipes crossed over:
///
///     client --writes--> pipeToServer   --reads--> server
///     client <--reads--  pipeToClient   <-writes-- server
/// </remarks>
internal sealed class InMemoryMcpServer : IAsyncDisposable
{
    private readonly Pipe _toServer = new();
    private readonly Pipe _toClient = new();
    private readonly McpServer _server;
    private readonly Task _serverLoop;

    private InMemoryMcpServer(IReadOnlyList<McpServerTool> tools, string serverName)
    {
        var transport = new StreamServerTransport(
            inputStream: _toServer.Reader.AsStream(),
            outputStream: _toClient.Writer.AsStream(),
            serverName: serverName,
            loggerFactory: NullLoggerFactory.Instance);

        var options = new McpServerOptions
        {
            ServerInfo = new Implementation { Name = serverName, Version = "1.0.0" },
        };

        foreach (var tool in tools)
        {
            options.ToolCollection ??= [];
            options.ToolCollection.Add(tool);
        }

        _server = McpServer.Create(
            transport, options, NullLoggerFactory.Instance, serviceProvider: null);

        _serverLoop = _server.RunAsync();
    }

    /// <summary>Starts a server exposing the supplied tools.</summary>
    public static InMemoryMcpServer Start(string serverName, params McpServerTool[] tools)
        => new(tools, serverName);

    /// <summary>
    /// A transport factory that routes every config to this server, for handing
    /// to <see cref="UpstreamRegistry.ConnectAsync"/>.
    /// </summary>
    public UpstreamTransportFactory TransportFactory => (_, _) =>
        new StreamClientTransport(
            serverInput: _toServer.Writer.AsStream(),
            serverOutput: _toClient.Reader.AsStream(),
            loggerFactory: NullLoggerFactory.Instance);

    public async ValueTask DisposeAsync()
    {
        await _toServer.Writer.CompleteAsync();
        await _toClient.Writer.CompleteAsync();

        try
        {
            await _server.DisposeAsync();
            await _serverLoop;
        }
        catch (Exception)
        {
            // Tearing down; a transport that is already closed is not a failure.
        }
    }
}
