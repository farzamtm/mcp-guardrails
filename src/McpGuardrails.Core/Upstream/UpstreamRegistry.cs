using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Authentication;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Upstream;

/// <summary>
/// Creates the transport used to reach one downstream server.
/// </summary>
/// <remarks>
/// A seam for testing. Production spawns a child process or opens an HTTP
/// connection, but a test can substitute an in-memory stream pair and talk to a
/// real MCP server running in the same process - no npx, no network, no spawned
/// binaries, and tests that still exercise the genuine protocol rather than a mock.
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
    IReadOnlyList<McpClientTool> Tools)
{
    /// <summary>The configuration it was connected from.</summary>
    /// <remarks>
    /// Optional so the record keeps its three-argument shape for tests that build
    /// one by hand; the registry always sets it.
    /// </remarks>
    public UpstreamServerConfig? Config { get; init; }
}

/// <summary>
/// A server the proxy started without: an <c>optional</c> one it could not
/// reach, or an OAuth one with no usable login.
/// </summary>
/// <param name="Name">The server's name.</param>
/// <param name="Reason">Why it could not be reached, for the operator's log and the model.</param>
public sealed record UnavailableUpstream(string Name, string Reason);

/// <summary>
/// A downstream server could not be reached at startup.
/// </summary>
/// <remarks>
/// Names the server, because "connection refused" alone does not say which of
/// eight configured servers refused it.
/// </remarks>
public sealed class UpstreamConnectionException(string server, Exception innerException)
    : Exception($"Could not connect to upstream server '{server}': {innerException.Message}", innerException)
{
    /// <summary>The server that failed.</summary>
    public string Server { get; } = server;
}

/// <summary>
/// Owns the connections to every downstream server and answers "which server
/// handles this tool?".
/// </summary>
/// <remarks>
/// This is the proxy's client half. The server half lives in the CLI's ServeCommand.
/// What to connect to comes from <see cref="ServersLoader"/>, or from
/// <see cref="DefaultUpstreams"/> when there is no servers file.
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

    private UpstreamRegistry(
        IReadOnlyList<UpstreamConnection> connections,
        IReadOnlyList<UnavailableUpstream> unavailable)
    {
        Unavailable = unavailable;
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

    /// <summary>Optional servers that could not be reached, in configuration order.</summary>
    public IReadOnlyList<UnavailableUpstream> Unavailable { get; }

    /// <summary>
    /// Spawns and connects to every configured server, then caches its tool list.
    /// </summary>
    /// <remarks>
    /// Connections are established in parallel. Each one spawns a child process
    /// and waits for it to boot; doing that sequentially would make startup the
    /// sum of every server's boot time instead of the slowest one. Task.WhenAll
    /// is the idiomatic way to await a set of concurrent operations.
    ///
    /// If a required server fails, the ones that did connect are shut down before
    /// the error propagates: a proxy that refuses to start must not leave child
    /// processes behind.
    /// </remarks>
    /// <exception cref="UpstreamConnectionException">A required server could not be reached.</exception>
    public static async Task<UpstreamRegistry> ConnectAsync(
        IReadOnlyList<UpstreamServerConfig> configs,
        ILoggerFactory loggerFactory,
        UpstreamTransportFactory? transportFactory = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configs);
        ArgumentNullException.ThrowIfNull(loggerFactory);

        transportFactory ??= CreateTransport;

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

        var attempts = await Task.WhenAll(
            configs.Select(c => TryConnectOneAsync(c, loggerFactory, transportFactory, cancellationToken)));

        var connections = new List<UpstreamConnection>();
        var unavailable = new List<UnavailableUpstream>();
        UpstreamConnectionException? failure = null;

        foreach (var (config, connection, error) in attempts)
        {
            if (connection is not null)
            {
                connections.Add(connection);
            }
            else if (UpstreamNeedsOperatorException.Find(error) is { } needed)
            {
                // Not fatal even when the server is required: no amount of
                // waiting fixes a missing login or credential; a person has to act,
                // and the rest of the configured servers are still worth serving.
                // Its tools are absent, and calls to them say what to do.
                unavailable.Add(new UnavailableUpstream(config.Name, needed.Message));
            }
            else if (config.Optional)
            {
                unavailable.Add(new UnavailableUpstream(config.Name, error!.Message));
            }
            else
            {
                failure ??= new UpstreamConnectionException(config.Name, error!);
            }
        }

        var registry = new UpstreamRegistry(connections, unavailable);

        if (failure is not null)
        {
            await registry.DisposeAsync();
            throw failure;
        }

        return registry;
    }

    /// <summary>
    /// Production transport: a child process for stdio, an HTTP connection for
    /// the remote transports.
    /// </summary>
    internal static IClientTransport CreateTransport(
        UpstreamServerConfig config,
        ILoggerFactory loggerFactory) => CreateTransport(config, loggerFactory, oauth: null);

    /// <summary>The production transport, with OAuth for a remote server that logs in.</summary>
    public static IClientTransport CreateTransport(
        UpstreamServerConfig config,
        ILoggerFactory loggerFactory,
        ClientOAuthOptions? oauth) =>
        config.Transport is UpstreamTransport.Stdio
            ? new StdioClientTransport(StdioOptions(config), loggerFactory)
            : new HttpClientTransport(HttpOptions(config, oauth), RemoteHttp, loggerFactory, ownsHttpClient: false);

    /// <summary>
    /// One HTTP client for every remote server, for the life of the process, as
    /// HttpClient is designed to be used.
    /// </summary>
    /// <remarks>
    /// Redirects are off, as for the webhook client: a 3xx would carry the
    /// configured Authorization header to a host the operator never named.
    /// </remarks>
    private static HttpClient RemoteHttp { get; } =
        new(new SocketsHttpHandler { AllowAutoRedirect = false });

    /// <summary>How a stdio config becomes the SDK's launch options.</summary>
    /// <remarks>
    /// internal rather than private so tests can verify the mapping without
    /// spawning a process. Silently dropping EnvironmentVariables or the
    /// inheritance switch here would break real deployments - or leak the
    /// proxy's secrets into a child - in a way no other test would catch.
    /// </remarks>
    internal static StdioClientTransportOptions StdioOptions(UpstreamServerConfig config)
    {
        var options = new StdioClientTransportOptions
        {
            Name = config.Name,
            Command = config.Command!,
            Arguments = [.. config.Arguments],
            EnvironmentVariables = config.EnvironmentVariables?.ToDictionary(
                kv => kv.Key, kv => kv.Value, StringComparer.Ordinal),
            InheritEnvironmentVariables = config.InheritEnvironment,
            WorkingDirectory = config.WorkingDirectory,
        };

        if (config.ShutdownTimeout is { } timeout)
        {
            options.ShutdownTimeout = timeout;
        }

        return options;
    }

    /// <summary>How a remote config becomes the SDK's HTTP options.</summary>
    /// <remarks>
    /// The transport mode is always explicit. The SDK's AutoDetect tries
    /// Streamable HTTP and silently falls back to SSE, which is a downgrade
    /// nobody chose; a server that only speaks SSE has to say <c>type: sse</c>.
    /// </remarks>
    internal static HttpClientTransportOptions HttpOptions(UpstreamServerConfig config, ClientOAuthOptions? oauth = null) => new()
    {
        Name = config.Name,
        OAuth = oauth,
        Endpoint = config.Url!,
        TransportMode = config.Transport is UpstreamTransport.Sse
            ? HttpTransportMode.Sse
            : HttpTransportMode.StreamableHttp,
        AdditionalHeaders = config.Headers?.ToDictionary(
            kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase),
    };

    private static async Task<(UpstreamServerConfig Config, UpstreamConnection? Connection, Exception? Error)>
        TryConnectOneAsync(
            UpstreamServerConfig config,
            ILoggerFactory loggerFactory,
            UpstreamTransportFactory transportFactory,
            CancellationToken cancellationToken)
    {
        try
        {
            return (config, await ConnectOneAsync(config, loggerFactory, transportFactory, cancellationToken), null);
        }
        catch (Exception ex)
        {
            // Caught for every server, not only optional ones, so the caller can
            // close what did connect before reporting the failure.
            return (config, null, ex);
        }
    }

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

        try
        {
            var tools = await client.ListToolsAsync(cancellationToken: cancellationToken);

            return new UpstreamConnection(config.Name, client, [.. tools]) { Config = config };
        }
        catch
        {
            // Connected but could not list: the client owns a live process or
            // session, and nothing else holds a reference to close it.
            await client.DisposeAsync();
            throw;
        }
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
    /// <remarks>
    /// <c>out Tool?</c> with <see cref="NotNullWhenAttribute"/> rather than a
    /// non-nullable out set to <c>null!</c>: the miss is real and the caller has
    /// to see it. Declaring it non-nullable would tell the compiler the value is
    /// always present, and with warnings-as-errors that silence is exactly what
    /// would let a future <c>tool.Annotations</c> compile clean and fail on the
    /// path every tool call takes.
    /// </remarks>
    public bool TryGetTool(string qualifiedToolName, [NotNullWhen(true)] out Tool? tool)
    {
        if (_byQualifiedName.TryGetValue(qualifiedToolName, out var entry))
        {
            // ProtocolTool, not the McpClientTool wrapper: the wrapper's Name can
            // disagree with the DTO's (see the note in ToolNamespacer), and policy
            // must see exactly what the client was told about.
            tool = entry.Tool.ProtocolTool;
            return true;
        }

        tool = null;
        return false;
    }

    /// <summary>
    /// The unavailable server a client-visible tool name would have belonged to.
    /// </summary>
    /// <remarks>
    /// Its tools were never listed, so the name cannot be resolved; but its
    /// prefix still says whose it was, and "server 'linear' needs a login" is a
    /// far better answer than "unknown tool" to a model that saw the tool in a
    /// previous session.
    /// </remarks>
    public bool TryGetUnavailable(string qualifiedToolName, [NotNullWhen(true)] out UnavailableUpstream? server)
    {
        var separator = qualifiedToolName.IndexOf(ToolNamespacer.Separator, StringComparison.Ordinal);
        server = separator > 0
            ? Unavailable.FirstOrDefault(u => string.Equals(u.Name, qualifiedToolName[..separator], StringComparison.Ordinal))
            : null;

        return server is not null;
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
