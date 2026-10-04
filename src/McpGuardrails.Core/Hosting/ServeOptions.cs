using System.Globalization;
using System.Net;
using McpGuardrails.Core.Access;
using McpGuardrails.Core.Budget;

namespace McpGuardrails.Core.Hosting;

/// <summary>How the proxy's server half is reached by the MCP client.</summary>
public enum Transport
{
    /// <summary>JSON-RPC over the process's stdin/stdout. The default.</summary>
    Stdio,

    /// <summary>Streamable HTTP, stateless.</summary>
    Http,
}

/// <summary>A command line the proxy refuses to start with.</summary>
public sealed class ServeOptionsException(string message) : Exception(message);

/// <summary>
/// The transport options from the command line, validated.
/// </summary>
/// <remarks>
/// Lives in Core rather than in the CLI so the part that decides what the proxy
/// exposes to the network is unit-tested, not just smoke-tested. Every ambiguous
/// or risky combination is an error rather than a guess: a security proxy that
/// silently listens somewhere other than where its operator thought is worse
/// than one that does not start.
/// </remarks>
/// <param name="Transport">Which transport serves the client.</param>
/// <param name="BindAddress">The interface the HTTP listener binds to.</param>
/// <param name="Port">The HTTP port; 0 asks the OS for a free one.</param>
/// <param name="BearerToken">The static token HTTP clients must present, if any.</param>
/// <param name="OAuth">
/// The policy's <c>access.oauth</c> block, when HTTP clients authenticate with
/// access tokens instead.
/// </param>
public sealed record ServeOptions(
    Transport Transport,
    IPAddress BindAddress,
    int Port,
    string? BearerToken,
    OAuthSettings? OAuth = null)
{
    /// <summary>The HTTP port when <c>--port</c> is not given.</summary>
    public const int DefaultPort = 7300;

    /// <summary>
    /// Shortest bearer token accepted. Long enough that it has to come from a
    /// generator (<c>openssl rand -hex 32</c>) rather than from someone's memory.
    /// </summary>
    public const int MinimumTokenLength = 16;

    /// <summary>The environment variable the bearer token is read from.</summary>
    /// <remarks>
    /// An environment variable, not a flag: command lines are visible to every
    /// user on the machine through <c>ps</c>.
    /// </remarks>
    public const string TokenVariable = "GUARDRAILS_HTTP_TOKEN";

    /// <summary>Stdio, which is what the proxy did before HTTP existed.</summary>
    public static ServeOptions Default { get; } =
        new(Transport.Stdio, IPAddress.Loopback, DefaultPort, null);

    /// <summary>Whether a client must present <see cref="BearerToken"/>.</summary>
    public bool RequiresToken => BearerToken is not null;

    /// <summary>How HTTP clients authenticate, for the startup log line.</summary>
    public string AuthenticationName => OAuth is not null
        ? "OAuth access tokens"
        : RequiresToken ? "bearer token" : "none (loopback only)";

    /// <summary>
    /// Reads <c>--transport</c>, <c>--port</c> and <c>--bind</c> out of the
    /// arguments and ignores everything else.
    /// </summary>
    /// <remarks>
    /// Other arguments are left alone because the host builder reads the same
    /// array as configuration and the CLI has commands of its own
    /// (<c>list-upstream</c>, <c>--explain</c>).
    /// </remarks>
    /// <param name="args">The process arguments.</param>
    /// <param name="bearerToken">The value of <see cref="TokenVariable"/>, or null.</param>
    /// <param name="oauth">The policy's <c>access.oauth</c> block, or null.</param>
    /// <exception cref="ServeOptionsException">The combination is invalid or unsafe.</exception>
    public static ServeOptions Parse(IReadOnlyList<string> args, string? bearerToken, OAuthSettings? oauth = null)
    {
        ArgumentNullException.ThrowIfNull(args);

        string? transport = null;
        string? port = null;
        string? bind = null;

        for (var i = 0; i < args.Count; i++)
        {
            switch (args[i])
            {
                case "--transport":
                    transport = Value(args, ref i, transport);
                    break;
                case "--port":
                    port = Value(args, ref i, port);
                    break;
                case "--bind":
                    bind = Value(args, ref i, bind);
                    break;
            }
        }

        var kind = transport switch
        {
            null or "stdio" => Transport.Stdio,
            "http" => Transport.Http,
            _ => throw new ServeOptionsException(
                $"Unknown transport '{transport}'. Use 'stdio' (the default) or 'http'."),
        };

        if (kind is Transport.Stdio)
        {
            // A port or address with stdio means the operator believes something
            // is listening on the network. Saying so beats starting a process
            // that quietly does something else.
            if (port is not null || bind is not null)
            {
                throw new ServeOptionsException(
                    "--port and --bind only apply to '--transport http'.");
            }

            // Unlike the token below, an access.oauth block over stdio is refused:
            // rules and budgets keyed on the principal would silently never
            // apply, and a deny rule that never matches fails open.
            if (oauth is not null)
            {
                throw new ServeOptionsException(
                    "The policy configures 'access.oauth', which only applies to '--transport http': over " +
                    "stdio no call has a principal, so rules and budgets keyed on one would never apply. " +
                    "Serve over HTTP, or remove the 'access' section.");
            }

            // The token is ignored rather than rejected: the variable may well be
            // set for the whole shell, and stdio has no network to protect.
            return Default;
        }

        var address = ParseAddress(bind);

        // Two ways in at once is two policies about who may call, and whichever
        // one the operator forgot about is the one an attacker uses.
        if (oauth is not null && bearerToken is not null)
        {
            throw new ServeOptionsException(
                $"Both {TokenVariable} and the policy's 'access.oauth' are set. Choose one: a static token " +
                "for a simple setup, or OAuth access tokens. Unset the variable or remove the 'access' section.");
        }

        return new ServeOptions(
            Transport.Http,
            address,
            ParsePort(port),
            ParseToken(bearerToken, address, oauth is not null),
            oauth);
    }

    /// <summary>
    /// Refuses a budget section this transport cannot enforce as written.
    /// </summary>
    /// <remarks>
    /// <c>budgets.session</c> promises a cap per client session. Stateless HTTP
    /// has no session, so the only thing the counter could hang off is the
    /// process: one pool, silently shared by every client for as long as the
    /// proxy runs. That is a different limit from the one the operator wrote,
    /// and a cap that would mean something other than it says is refused rather
    /// than reinterpreted. <c>budgets.daily</c> is unaffected - it is persisted
    /// and process-wide by design, so it means the same over either transport.
    /// </remarks>
    /// <param name="budgets">The policy's validated budget section.</param>
    /// <exception cref="ServeOptionsException">
    /// The transport is HTTP and a session budget is configured.
    /// </exception>
    public void EnsureEnforceable(BudgetPolicy budgets)
    {
        ArgumentNullException.ThrowIfNull(budgets);

        if (Transport is Transport.Http && budgets.Session is not null)
        {
            throw new ServeOptionsException(
                $"'budgets.{BudgetGate.SessionScope}' cannot be enforced over '--transport http': " +
                "stateless HTTP has no session, so the cap would be one pool shared by every " +
                $"client for the life of the process. Use 'budgets.{BudgetGate.DailyScope}' " +
                "(persisted, and process-wide by design), " +
                $"'budgets.{BudgetGate.PrincipalScope}' with 'access.oauth' (one cap per caller), " +
                "or serve over stdio.");
        }
    }

    private static string Value(IReadOnlyList<string> args, ref int i, string? existing)
    {
        var flag = args[i];

        if (existing is not null)
        {
            throw new ServeOptionsException($"{flag} was given more than once.");
        }

        if (i + 1 >= args.Count || args[i + 1].StartsWith("--", StringComparison.Ordinal))
        {
            throw new ServeOptionsException($"{flag} needs a value.");
        }

        i++;
        return args[i];
    }

    private static IPAddress ParseAddress(string? bind)
    {
        if (bind is null)
        {
            return IPAddress.Loopback;
        }

        // IP literals only. A host name resolves to whatever DNS says at startup,
        // which is not a decision about which interface to expose.
        if (!IPAddress.TryParse(bind, out var address))
        {
            throw new ServeOptionsException(
                $"--bind '{bind}' is not an IP address. Use e.g. 127.0.0.1, ::1 or 0.0.0.0.");
        }

        return address;
    }

    private static int ParsePort(string? port)
    {
        if (port is null)
        {
            return DefaultPort;
        }

        if (!int.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, out var value) ||
            value > IPEndPoint.MaxPort)
        {
            throw new ServeOptionsException(
                $"--port '{port}' is not a port number between 0 and {IPEndPoint.MaxPort}.");
        }

        return value;
    }

    private static string? ParseToken(string? token, IPAddress address, bool oauth)
    {
        if (token is not null && token.Trim().Length < MinimumTokenLength)
        {
            // Set but useless is treated as a mistake, not as "no token": the
            // operator plainly meant to require one.
            throw new ServeOptionsException(
                $"{TokenVariable} must be at least {MinimumTokenLength} characters " +
                "(try: openssl rand -hex 32).");
        }

        // Anything that can reach a non-loopback listener can drive every
        // downstream tool, so exposing one without authentication - a token, or
        // OAuth - is not an option offered at all.
        if (token is null && !oauth && !IPAddress.IsLoopback(address))
        {
            throw new ServeOptionsException(
                $"Refusing to bind {address} without authentication: anyone who can reach " +
                $"it could call every downstream tool. Set {TokenVariable}, configure " +
                "'access.oauth' in the policy, or bind to 127.0.0.1.");
        }

        return token?.Trim();
    }
}
