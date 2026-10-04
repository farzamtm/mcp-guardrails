using System.Text.RegularExpressions;

namespace McpGuardrails.Core.Upstream;

/// <summary>How the proxy reaches a downstream server.</summary>
public enum UpstreamTransport
{
    /// <summary>Spawn a child process and speak JSON-RPC over its stdin/stdout.</summary>
    Stdio,

    /// <summary>Streamable HTTP, the current MCP remote transport.</summary>
    Http,

    /// <summary>The older HTTP+SSE transport, for servers that have not moved on.</summary>
    Sse,
}

/// <summary>
/// Describes one downstream MCP server the proxy should front.
/// </summary>
/// <remarks>
/// Transport-neutral: a stdio server has a <see cref="Command"/>, a remote one a
/// <see cref="Url"/>, and <see cref="Validate"/> refuses a config that mixes them.
/// Every value here is already expanded - <c>${VAR}</c> references were resolved
/// by <see cref="ServersLoader"/> - except <see cref="DisplayTemplate"/>, which
/// keeps the file's text so it can be shown without revealing what it expanded to.
///
/// C# notes:
///
/// - `record` generates a constructor, value equality, a readable ToString() and
///   `with`-expressions for you. Use records for data, classes for behaviour.
///
/// - `required` means the compiler refuses to let you construct this without
///   setting the property. It gives you constructor-style safety while keeping
///   the readable object-initializer syntax.
///
/// - `init` means the property can be set while constructing the object and never
///   again. Shallow immutability without writing a constructor by hand.
/// </remarks>
public sealed partial record UpstreamServerConfig
{
    /// <summary>
    /// Short identifier used to namespace this server's tools, e.g. "fs" produces
    /// tools called "fs__read_file".
    /// </summary>
    public required string Name { get; init; }

    /// <summary>How to reach the server. Stdio unless the servers file says otherwise.</summary>
    public UpstreamTransport Transport { get; init; } = UpstreamTransport.Stdio;

    /// <summary>Executable to spawn, e.g. "npx". Stdio only.</summary>
    public string? Command { get; init; }

    /// <summary>
    /// Arguments passed to <see cref="Command"/>.
    /// </summary>
    /// <remarks>
    /// Exposed as IReadOnlyList so callers cannot mutate our copy. `= []` is a
    /// collection expression - the modern way to write an empty collection.
    /// </remarks>
    public IReadOnlyList<string> Arguments { get; init; } = [];

    /// <summary>
    /// Environment variables for the child process: added to the proxy's own
    /// when <see cref="InheritEnvironment"/> is true, and the child's entire
    /// environment when it is false.
    /// </summary>
    public IReadOnlyDictionary<string, string?>? EnvironmentVariables { get; init; }

    /// <summary>
    /// Whether the child starts with a copy of the proxy's environment.
    /// </summary>
    /// <remarks>
    /// True by default, which is how every stdio server has been launched so far.
    /// The servers file sets it to false under <c>env_isolation: true</c>, so a
    /// downstream server never sees the proxy's API keys or another server's
    /// token unless the file passes them on.
    /// </remarks>
    public bool InheritEnvironment { get; init; } = true;

    /// <summary>Working directory for the child process. Stdio only.</summary>
    public string? WorkingDirectory { get; init; }

    /// <summary>How long a child gets to exit on shutdown before it is killed. Stdio only.</summary>
    public TimeSpan? ShutdownTimeout { get; init; }

    /// <summary>The server's endpoint. Http and Sse only.</summary>
    public Uri? Url { get; init; }

    /// <summary>Static headers sent with every request. Http and Sse only.</summary>
    public IReadOnlyDictionary<string, string>? Headers { get; init; }

    /// <summary>
    /// Log in with OAuth rather than send a static header. Http and Sse only.
    /// </summary>
    /// <remarks>
    /// The tokens never live here or in the servers file: <c>auth login</c>
    /// stores them in the OS credential store, and the proxy reads them from
    /// there at startup.
    /// </remarks>
    public UpstreamOAuthSettings? OAuth { get; init; }

    /// <summary>
    /// The container this stdio server runs in, or null when it runs directly on
    /// the host.
    /// </summary>
    /// <remarks>
    /// Descriptive only: by the time a config exists, <see cref="Command"/> and
    /// <see cref="Arguments"/> already are the generated <c>docker run</c> line, so
    /// the transport launches the container without knowing it is one. Kept so
    /// <c>validate</c> can say what the server can reach.
    /// </remarks>
    public ContainerIsolation? Isolation { get; init; }

    /// <summary>
    /// Whether the proxy may start without this server when it cannot be reached.
    /// </summary>
    /// <remarks>
    /// False by default: a server the operator configured and the proxy silently
    /// dropped is a tool set nobody reviewed. Opting in means its tools are
    /// absent for the session and calls to them fail as unknown tools.
    /// </remarks>
    public bool Optional { get; init; }

    /// <summary>
    /// How the server was written in the servers file, before expansion: the
    /// command line, or the URL.
    /// </summary>
    /// <remarks>
    /// What <c>list-upstream</c>, <c>validate</c> and the audit log show. A
    /// <c>${GITHUB_TOKEN}</c> reference is safe to print; its value is not.
    /// Null for servers defined in code.
    /// </remarks>
    public string? DisplayTemplate { get; init; }

    /// <summary>
    /// What a stdio server can reach on this machine, in one line; null for a
    /// remote server, which reaches nothing here but the proxy.
    /// </summary>
    /// <remarks>
    /// For <c>validate</c>: the question a reviewer of a servers file actually
    /// has is not "what command is this" but "what can it touch".
    /// </remarks>
    public string? Reach() => Transport is not UpstreamTransport.Stdio
        ? null
        : Isolation?.Describe() ??
          "everything you can: it runs directly on the host as you, with your files and network " +
          "(add 'x-guardrails.isolation' to run it in a container)";

    /// <summary>
    /// Server names must be letters, digits and hyphens only.
    /// </summary>
    /// <remarks>
    /// Underscores are deliberately excluded. Tool namespacing joins the server
    /// name and tool name with a double underscore ("fs" + "__" + "read_file").
    /// If a server name could itself contain "__", splitting the combined name
    /// back apart would be ambiguous. Forbidding it here makes the round trip
    /// provably reversible instead of merely usually correct.
    /// </remarks>
    [GeneratedRegex("^[a-zA-Z0-9-]+$")]
    private static partial Regex NamePattern { get; }

    /// <summary>True when <paramref name="name"/> is a legal server name.</summary>
    public static bool IsValidName(string name) => NamePattern.IsMatch(name);

    /// <summary>
    /// Throws if this config is malformed. Call once at startup: a bad config
    /// should kill the process immediately, not produce a confusing failure later.
    /// </summary>
    public void Validate()
    {
        // ArgumentException.ThrowIfNullOrWhiteSpace is a "throw helper". The
        // [CallerArgumentExpression] attribute inside it captures the caller's
        // expression text, so the message names the offending property for free.
        ArgumentException.ThrowIfNullOrWhiteSpace(Name);

        if (!IsValidName(Name))
        {
            throw new ArgumentException(
                $"Upstream server name '{Name}' is invalid. " +
                "Use letters, digits and hyphens only (no underscores).",
                nameof(Name));
        }

        if (Transport is UpstreamTransport.Stdio)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(Command);

            if (Url is not null)
            {
                throw new ArgumentException(
                    $"Upstream server '{Name}' is stdio but has a URL.", nameof(Url));
            }

            if (OAuth is not null)
            {
                throw new ArgumentException(
                    $"Upstream server '{Name}' is stdio but has OAuth settings.", nameof(OAuth));
            }

            return;
        }

        if (!Enum.IsDefined(Transport))
        {
            throw new ArgumentException(
                $"Upstream server '{Name}' has an unknown transport.", nameof(Transport));
        }

        if (Url is null)
        {
            throw new ArgumentException(
                $"Upstream server '{Name}' is a remote server but has no URL.", nameof(Url));
        }

        if (Command is not null)
        {
            throw new ArgumentException(
                $"Upstream server '{Name}' is a remote server but has a command.", nameof(Command));
        }

        if (Isolation is not null)
        {
            throw new ArgumentException(
                $"Upstream server '{Name}' is a remote server but has container isolation.", nameof(Isolation));
        }
    }
}
