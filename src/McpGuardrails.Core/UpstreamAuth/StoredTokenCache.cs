using System.Text.Json;
using System.Text.Json.Serialization;
using ModelContextProtocol.Authentication;

namespace McpGuardrails.Core.UpstreamAuth;

/// <summary>What the credential store holds for one server.</summary>
/// <remarks>
/// The SDK's token container plus the URL the tokens were issued for, mapped
/// field by field into this repository's own record: the SDK type is not
/// registered with a source-generated serializer here, and its shape is the
/// SDK's to change.
/// </remarks>
internal sealed record StoredTokens
{
    [JsonPropertyName("version")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("server_url")]
    public required string ServerUrl { get; init; }

    [JsonPropertyName("token_type")]
    public string? TokenType { get; init; }

    [JsonPropertyName("access_token")]
    public string? AccessToken { get; init; }

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; init; }

    [JsonPropertyName("expires_in")]
    public int? ExpiresIn { get; init; }

    [JsonPropertyName("scope")]
    public string? Scope { get; init; }

    [JsonPropertyName("obtained_at")]
    public DateTimeOffset ObtainedAt { get; init; }

    [JsonPropertyName("client_id")]
    public string? ClientId { get; init; }

    [JsonPropertyName("client_secret")]
    public string? ClientSecret { get; init; }

    [JsonPropertyName("token_endpoint_auth_method")]
    public string? TokenEndpointAuthMethod { get; init; }

    [JsonPropertyName("authorization_server")]
    public string? AuthorizationServer { get; init; }
}

[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(StoredTokens))]
internal sealed partial class StoredTokensJsonContext : JsonSerializerContext;

/// <summary>What is stored for a server, for <c>auth status</c>.</summary>
public enum LoginState
{
    /// <summary>Nothing stored: <c>auth login</c> has not been run, or was undone.</summary>
    None,

    /// <summary>Tokens for this server's URL.</summary>
    LoggedIn,

    /// <summary>Tokens for a different URL, which are never sent to this one.</summary>
    OtherUrl,

    /// <summary>Something is stored, but not something this proxy wrote.</summary>
    Unreadable,
}

/// <summary>A server's login, as <c>auth status</c> reports it.</summary>
/// <param name="State">Whether there is a usable login.</param>
/// <param name="ExpiresAt">When the access token expires, if the server said.</param>
/// <param name="CanRefresh">Whether a refresh token was issued, so the login outlives the access token.</param>
/// <param name="Problem">Why the store could not be read, when that is why the state is <see cref="LoginState.Unreadable"/>.</param>
public sealed record LoginStatus(
    LoginState State, DateTimeOffset? ExpiresAt = null, bool CanRefresh = false, string? Problem = null);

/// <summary>
/// The SDK's token cache, kept in a credential store and bound to one server URL.
/// </summary>
/// <remarks>
/// The binding is the point. Tokens are stored under the server's name, and a
/// servers file can be edited to point that name somewhere else; tokens issued
/// for <c>https://mcp.linear.app</c> must never be presented to whatever the
/// name points at now. So a stored login for another URL reads as no login at
/// all, and the operator logs in again.
///
/// Anything unreadable also reads as no login: the proxy then refuses the
/// server's tools and says to run <c>auth login</c>, which is the closed state.
/// That includes a store that cannot be read right now - a locked keychain, a
/// keyring that did not unlock - so one server's credential trouble never stops
/// the proxy serving the others.
/// </remarks>
public sealed class StoredTokenCache : ITokenCache
{
    private readonly ITokenStore _store;
    private readonly string _server;
    private readonly string _url;
    private readonly Lock _writing = new();
    private bool _ignoreStored;

    /// <param name="store">Where the tokens live.</param>
    /// <param name="server">The server's name in the servers file.</param>
    /// <param name="url">The server's URL; stored tokens for any other are ignored.</param>
    /// <param name="ignoreStored">
    /// Start as if nothing were stored, for <c>auth login</c>: a fresh login
    /// registers and authorizes afresh rather than reusing a client registered
    /// with another redirect URI. What it obtains is still stored.
    /// </param>
    public StoredTokenCache(ITokenStore store, string server, Uri url, bool ignoreStored = false)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrWhiteSpace(server);
        ArgumentNullException.ThrowIfNull(url);

        _store = store;
        _server = server;
        _url = url.AbsoluteUri;
        _ignoreStored = ignoreStored;
    }

    /// <summary>
    /// Set when serving: a refresh whose tokens cannot be stored then fails as
    /// "needs a new login" - a tool error the model passes on - instead of an
    /// exception from deep inside the SDK's request.
    /// </summary>
    public bool ForServing { get; init; }

    /// <summary>What is stored for this server.</summary>
    public LoginStatus Status()
    {
        var (state, tokens, problem) = Load();

        return state is LoginState.LoggedIn
            ? new LoginStatus(
                state,
                tokens!.ExpiresIn is { } seconds ? tokens.ObtainedAt.AddSeconds(seconds) : null,
                !string.IsNullOrEmpty(tokens.RefreshToken))
            : new LoginStatus(state, Problem: problem);
    }

    public ValueTask<TokenContainer?> GetTokensAsync(CancellationToken cancellationToken = default)
    {
        if (_ignoreStored)
        {
            return ValueTask.FromResult<TokenContainer?>(null);
        }

        var (state, tokens, _) = Load();

        return ValueTask.FromResult(state is LoginState.LoggedIn
            ? new TokenContainer
            {
                TokenType = tokens!.TokenType!,
                AccessToken = tokens.AccessToken!,
                RefreshToken = tokens.RefreshToken,
                ExpiresIn = tokens.ExpiresIn,
                Scope = tokens.Scope,
                ObtainedAt = tokens.ObtainedAt,
                ClientId = tokens.ClientId,
                ClientSecret = tokens.ClientSecret,
                TokenEndpointAuthMethod = tokens.TokenEndpointAuthMethod,
                AuthorizationServer = tokens.AuthorizationServer,
            }
            : null);
    }

    public ValueTask StoreTokensAsync(TokenContainer tokens, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tokens);

        // One writer at a time: a refresh racing a refresh would otherwise be
        // decided by whichever store write landed last.
        lock (_writing)
        {
            // RFC 6749 section 6 lets a refresh response leave out refresh_token
            // when the server does not rotate them, and the SDK passes that on as
            // null. Storing it as given would throw the refresh token away on the
            // first refresh and turn "refreshed automatically" into a one-hour
            // login. Only ever carried over from this server's own login.
            var refreshToken = tokens.RefreshToken;
            if (string.IsNullOrEmpty(refreshToken) && !_ignoreStored &&
                Load() is (LoginState.LoggedIn, { } stored, _))
            {
                refreshToken = stored.RefreshToken;
            }

            var json = JsonSerializer.Serialize(
                new StoredTokens
                {
                    ServerUrl = _url,
                    TokenType = tokens.TokenType,
                    AccessToken = tokens.AccessToken,
                    RefreshToken = refreshToken,
                    ExpiresIn = tokens.ExpiresIn,
                    Scope = tokens.Scope,
                    ObtainedAt = tokens.ObtainedAt,
                    ClientId = tokens.ClientId,
                    ClientSecret = tokens.ClientSecret,
                    TokenEndpointAuthMethod = tokens.TokenEndpointAuthMethod,
                    AuthorizationServer = tokens.AuthorizationServer,
                },
                StoredTokensJsonContext.Default.StoredTokens);

            try
            {
                _store.Write(_server, json);
            }
            catch (TokenStoreException ex) when (ForServing)
            {
                throw new UpstreamLoginRequiredException(
                    _server, $"could not save its refreshed tokens ({ex.Message}) and needs a new login");
            }

            // Once something is stored, later reads see it: the login has happened.
            _ignoreStored = false;
        }

        return ValueTask.CompletedTask;
    }

    private (LoginState State, StoredTokens? Tokens, string? Problem) Load()
    {
        string? json;
        try
        {
            json = _store.Read(_server);
        }
        catch (TokenStoreException ex)
        {
            return (LoginState.Unreadable, null, ex.Message);
        }

        if (json is null)
        {
            return (LoginState.None, null, null);
        }

        StoredTokens? tokens;
        try
        {
            tokens = JsonSerializer.Deserialize(json, StoredTokensJsonContext.Default.StoredTokens);
        }
        catch (JsonException)
        {
            return (LoginState.Unreadable, null, null);
        }

        if (tokens is null || string.IsNullOrEmpty(tokens.AccessToken) || string.IsNullOrEmpty(tokens.TokenType))
        {
            return (LoginState.Unreadable, null, null);
        }

        return string.Equals(tokens.ServerUrl, _url, StringComparison.Ordinal)
            ? (LoginState.LoggedIn, tokens, null)
            : (LoginState.OtherUrl, null, null);
    }
}
