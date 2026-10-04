using McpGuardrails.Core.Upstream;
using ModelContextProtocol.Authentication;
using ModelContextProtocol.Client;

namespace McpGuardrails.Core.UpstreamAuth;

/// <summary>
/// A remote server that needs someone to run <c>auth login</c> before the proxy
/// can use it.
/// </summary>
/// <param name="server">The server's name.</param>
/// <param name="why">What happened, as a clause: "has never been logged in".</param>
public sealed class UpstreamLoginRequiredException(string server, string why)
    : UpstreamNeedsOperatorException(server, $"Server '{server}' {why}: run 'mcp-guardrails auth login {server}'.");

/// <summary>
/// The SDK's OAuth client settings for a remote server, for the two ways the
/// proxy uses them: interactively in <c>auth login</c>, and silently when it
/// serves.
/// </summary>
/// <remarks>
/// Everything the protocol needs - protected resource discovery, authorization
/// server metadata, dynamic client registration, PKCE, the code exchange, the
/// refresh - is the SDK's ClientOAuthProvider. What is decided here is where the
/// tokens live and, above all, that <b>serving never opens a browser</b>: a stdio
/// child of Claude Desktop has nowhere reliable to show one, and a login prompt
/// that appears from nowhere is exactly what a phishing page looks like. When
/// serving, a login the SDK cannot complete silently fails with
/// <see cref="UpstreamLoginRequiredException"/>, which ends up in front of the
/// model as "tell the user to run auth login".
/// </remarks>
public static class UpstreamOAuth
{
    /// <summary>
    /// Settings for serving: stored tokens only, refreshed when they expire,
    /// never interactive.
    /// </summary>
    /// <exception cref="UpstreamLoginRequiredException">Nothing usable is stored for the server.</exception>
    public static ClientOAuthOptions ForServing(UpstreamServerConfig config, ITokenStore store)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(store);

        var oauth = config.OAuth ?? throw new ArgumentException($"Server '{config.Name}' has no OAuth settings.", nameof(config));
        var cache = new StoredTokenCache(store, config.Name, config.Url!) { ForServing = true };

        // Checked before connecting rather than left to the SDK: with no tokens it
        // would register a new client with the authorization server on every
        // start, only to stop at the step that needs a person.
        var status = cache.Status();
        switch (status.State)
        {
            case LoginState.None:
                throw new UpstreamLoginRequiredException(config.Name, "has never been logged in");
            case LoginState.OtherUrl:
                throw new UpstreamLoginRequiredException(config.Name, "was logged in at a different URL");
            case LoginState.Unreadable when status.Problem is { } problem:
                throw new UpstreamLoginRequiredException(config.Name, $"has a stored login that could not be read ({problem})");
            case LoginState.Unreadable:
                throw new UpstreamLoginRequiredException(config.Name, "has a stored login this proxy cannot read");
        }

        return new ClientOAuthOptions
        {
            // Required by the SDK, used only by an interactive login, which the
            // handler below refuses.
            RedirectUri = new Uri("http://127.0.0.1/callback"),
            ClientId = oauth.ClientId,
            Scopes = oauth.Scopes.Count > 0 ? oauth.Scopes : null,
            TokenCache = cache,
            AuthorizationCallbackHandler = (_, _) =>
                throw new UpstreamLoginRequiredException(config.Name, "needs a new login (its tokens expired and could not be refreshed)"),
        };
    }

    /// <summary>Settings for <c>auth login</c>: a fresh login through the given browser step.</summary>
    /// <param name="config">The server.</param>
    /// <param name="store">Where the tokens it obtains are stored.</param>
    /// <param name="redirectUri">The loopback URL the browser comes back to.</param>
    /// <param name="authorize">Shows the user the authorization URL and waits for the redirect.</param>
    public static ClientOAuthOptions ForLogin(
        UpstreamServerConfig config,
        ITokenStore store,
        Uri redirectUri,
        Func<AuthorizationCallbackContext, CancellationToken, Task<AuthorizationResult?>> authorize)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(redirectUri);
        ArgumentNullException.ThrowIfNull(authorize);

        var oauth = config.OAuth ?? throw new ArgumentException($"Server '{config.Name}' has no OAuth settings.", nameof(config));

        return new ClientOAuthOptions
        {
            RedirectUri = redirectUri,
            ClientId = oauth.ClientId,
            Scopes = oauth.Scopes.Count > 0 ? oauth.Scopes : null,
            TokenCache = new StoredTokenCache(store, config.Name, config.Url!, ignoreStored: true),
            AuthorizationCallbackHandler = authorize,
            DynamicClientRegistration = new DynamicClientRegistrationOptions { ClientName = "mcp-guardrails" },
        };
    }

    /// <summary>
    /// The transport factory for serving: OAuth servers get their stored login,
    /// every other server the plain transport.
    /// </summary>
    public static UpstreamTransportFactory ServingTransports(ITokenStore store)
    {
        ArgumentNullException.ThrowIfNull(store);

        return (config, loggerFactory) => config.OAuth is null
            ? UpstreamRegistry.CreateTransport(config, loggerFactory)
            : UpstreamRegistry.CreateTransport(config, loggerFactory, ForServing(config, store));
    }
}
