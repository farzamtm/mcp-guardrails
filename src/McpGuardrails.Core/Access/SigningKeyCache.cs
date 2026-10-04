using System.Net;
using System.Text.Json;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace McpGuardrails.Core.Access;

/// <summary>A signing-key problem that stops the proxy from validating tokens.</summary>
public sealed class OAuthException(string message) : Exception(message);

/// <summary>The keys to verify a token against, or a statement that there are none fit to use.</summary>
/// <param name="Keys">The issuer's current signing keys; null when they are too old to trust.</param>
public readonly record struct KeyLookup(IReadOnlyList<SecurityKey>? Keys)
{
    /// <summary>True when the last successful fetch is older than the maximum age.</summary>
    public bool IsExpired => Keys is null;
}

/// <summary>
/// The authorization server's signing keys: discovered and fetched at startup,
/// refetched on a schedule and on an unknown key id, and refused once too old.
/// </summary>
/// <remarks>
/// Written here rather than taken from the ASP.NET configuration manager
/// because the failure behaviour is the security design, and it has to be
/// exactly this:
/// <list type="bullet">
/// <item>Keys that cannot be fetched at startup stop the proxy. Serving with no
/// keys would refuse every request; serving with "skip validation" is not on
/// the table.</item>
/// <item>Keys that cannot be refetched later keep working until
/// <c>jwks_max_age_s</c>, so a short outage at the authorization server is not
/// an outage here, and then every request is refused: a key the issuer may have
/// revoked hours ago is not trusted forever because the issuer went quiet.</item>
/// <item>An unknown <c>kid</c> triggers a refetch, which is how key rotation is
/// picked up between scheduled refreshes - at most once per
/// <see cref="RetryCooldown"/>, so a stream of tokens with made-up key ids
/// cannot turn the proxy into a request amplifier against the issuer.</item>
/// <item>A refetch is shared work, so it runs under the cache's own lifetime,
/// never under the request that happened to trigger it. A client that
/// disconnects mid-fetch stops waiting; the fetch carries on for everyone
/// else, instead of being abandoned and then held off by the cooldown while
/// tokens signed with a rotated key are refused.</item>
/// </list>
/// Only RSA and EC signature keys are kept. A symmetric (<c>oct</c>) key in a
/// published key set would let anyone who read it mint tokens, and refusing it
/// here means no algorithm setting downstream can ever select it.
/// </remarks>
public sealed class SigningKeyCache : IDisposable
{
    /// <summary>The largest metadata or key set document read.</summary>
    public const int MaxDocumentBytes = 1024 * 1024;

    /// <summary>The shortest gap between two fetches not on the refresh schedule.</summary>
    public static readonly TimeSpan RetryCooldown = TimeSpan.FromSeconds(60);

    /// <summary>How long one fetch may take.</summary>
    public static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(10);

    private readonly OAuthSettings _settings;
    private readonly HttpClient _http;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _lifetime = new();

    // Guards _refresh and _lastAttemptTicks together, so deciding to start a
    // refresh and recording the attempt is one step. Never held across I/O.
    private readonly Lock _gate = new();

    private Uri? _jwksUri;
    private volatile KeySnapshot? _snapshot;
    private long _lastAttemptTicks;
    private Task? _refresh;

    /// <param name="settings">The validated <c>access.oauth</c> block.</param>
    /// <param name="handler">
    /// The transport. In production a handler with redirects disabled, so a
    /// compromised or misconfigured endpoint cannot bounce the fetch somewhere
    /// the URL checks never saw.
    /// </param>
    /// <param name="time">The clock; the system clock when null.</param>
    /// <param name="logger">Where failed refreshes are reported.</param>
    public SigningKeyCache(
        OAuthSettings settings,
        HttpMessageHandler handler,
        TimeProvider? time = null,
        ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(handler);

        _settings = settings;
        _http = new HttpClient(handler)
        {
            Timeout = FetchTimeout,
            // The size of what a remote server sends is its decision, and the
            // memory is ours: HttpClient enforces this while buffering, without
            // trusting Content-Length.
            MaxResponseContentBufferSize = MaxDocumentBytes,
        };
        _time = time ?? TimeProvider.System;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>A handler fit for fetching keys: see <see cref="OutboundHttp.CreateHandler"/>.</summary>
    public static SocketsHttpHandler CreateHandler() => OutboundHttp.CreateHandler();

    /// <summary>When the keys in use were fetched, or null before <see cref="InitializeAsync"/>.</summary>
    public DateTimeOffset? FetchedAt => _snapshot?.FetchedAt;

    /// <summary>Where the keys come from, once known.</summary>
    public Uri? JwksUri => _jwksUri;

    /// <summary>Discovers the key set and fetches it, or throws.</summary>
    /// <exception cref="OAuthException">The keys could not be found or fetched.</exception>
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        var now = _time.GetUtcNow();

        lock (_gate)
        {
            _lastAttemptTicks = now.UtcTicks;
        }

        try
        {
            _jwksUri = _settings.JwksUriValue ?? await DiscoverAsync(cancellationToken);
            _snapshot = new KeySnapshot(await FetchKeysAsync(_jwksUri, cancellationToken), now);
        }
        catch (Exception ex) when (IsFetchFailure(ex, cancellationToken))
        {
            throw new OAuthException(
                $"Cannot fetch the signing keys of the issuer '{_settings.Issuer}': {Describe(ex)}. " +
                "Without them no token can be validated, so the proxy does not start.");
        }
    }

    /// <summary>The keys to validate a token against.</summary>
    /// <param name="keyId">The token's <c>kid</c>, if it has one.</param>
    /// <param name="cancellationToken">The request's cancellation.</param>
    public async ValueTask<KeyLookup> GetKeysAsync(string? keyId, CancellationToken cancellationToken = default)
    {
        var snapshot = _snapshot
                       ?? throw new InvalidOperationException("InitializeAsync must complete before keys are looked up.");

        var now = _time.GetUtcNow();
        var due = now - snapshot.FetchedAt >= _settings.JwksRefresh;
        var unknown = keyId is not null && !snapshot.Has(keyId);

        if ((due || unknown) && Refresh(now, joinRunning: unknown) is { } refresh)
        {
            // WaitAsync, so a request that gives up stops waiting without
            // cancelling a fetch other requests depend on.
            await refresh.WaitAsync(cancellationToken);
            snapshot = _snapshot!;
        }

        return now - snapshot.FetchedAt > _settings.JwksMaxAge
            ? new KeyLookup(null)
            : new KeyLookup(snapshot.Keys);
    }

    /// <summary>The refresh to wait for, or null to go on with the keys there are.</summary>
    /// <param name="now">When the caller looked.</param>
    /// <param name="joinRunning">
    /// Whether to wait for a refresh already under way. True for an unknown key
    /// id: the refresh in flight is exactly what may make that token valid, so
    /// answering from the old keys would refuse it for nothing. False for a
    /// scheduled refresh: the keys there are stay valid until the maximum age,
    /// so the request need not wait.
    /// </param>
    /// <remarks>
    /// One refresh at a time, and at most one start per
    /// <see cref="RetryCooldown"/>, both decided under one lock so two requests
    /// that look at the same moment cannot fetch back to back.
    /// </remarks>
    private Task? Refresh(DateTimeOffset now, bool joinRunning)
    {
        lock (_gate)
        {
            if (_refresh is { IsCompleted: false } running)
            {
                return joinRunning ? running : null;
            }

            if (now.UtcTicks - _lastAttemptTicks < RetryCooldown.Ticks)
            {
                return null;
            }

            _lastAttemptTicks = now.UtcTicks;
            return _refresh = RefreshAsync(now);
        }
    }

    /// <remarks>
    /// A fetch failure is logged and the old keys stay in use, so every request
    /// awaiting this sees it complete; only a bug surfaces, as it would anywhere
    /// else. The cache's token is taken before the first await, while the cache
    /// is certainly alive, so a dispose that races the start reads as the
    /// cancellation it is.
    /// </remarks>
    private async Task RefreshAsync(DateTimeOffset now)
    {
        var lifetime = _lifetime.Token;

        // Off the caller's stack and out of the lock that started it, so the
        // fetch never runs synchronously inside Refresh.
        await Task.Yield();

        try
        {
            _snapshot = new KeySnapshot(await FetchKeysAsync(_jwksUri!, lifetime), now);
        }
        catch (Exception ex) when (IsFetchFailure(ex, lifetime))
        {
            _logger.LogWarning(
                "Cannot refresh the signing keys from {JwksUri}: {Reason}. The keys fetched at {FetchedAt:u} stay in use until they are {MaxAge} old.",
                _jwksUri,
                Describe(ex),
                _snapshot!.FetchedAt,
                _settings.JwksMaxAge);
        }
        catch (Exception) when (lifetime.IsCancellationRequested)
        {
            // Disposed mid-fetch, whether the fetch saw the cancellation or the
            // disposed client first: nobody is left to use the keys.
        }
    }

    /// <remarks>
    /// OpenID Connect Discovery first, because that is what Entra ID, Okta,
    /// Auth0 and Keycloak all serve; RFC 8414 second, for authorization servers
    /// that only speak plain OAuth. The document must name the configured issuer
    /// exactly - both specifications require the check, and it is what stops a
    /// metadata document from one server pointing at another's keys.
    /// </remarks>
    private async Task<Uri> DiscoverAsync(CancellationToken cancellationToken)
    {
        var issuer = _settings.IssuerUri;
        var path = issuer.AbsolutePath.TrimEnd('/');
        var origin = issuer.GetLeftPart(UriPartial.Authority);

        Uri[] candidates =
        [
            new($"{origin}{path}/.well-known/openid-configuration"),
            new($"{origin}/.well-known/oauth-authorization-server{path}"),
        ];

        foreach (var candidate in candidates)
        {
            if (await GetAsync(candidate, cancellationToken) is not { } body)
            {
                continue;
            }

            var document = JsonSerializer.Deserialize(body, AccessJsonContext.Default.AuthorizationServerDocument)
                           ?? throw new OAuthException($"'{candidate}' is not a metadata document");

            if (!string.Equals(document.Issuer, _settings.Issuer, StringComparison.Ordinal))
            {
                throw new OAuthException(
                    $"the metadata at '{candidate}' names a different issuer, so its keys are not this issuer's");
            }

            if (string.IsNullOrWhiteSpace(document.JwksUri))
            {
                throw new OAuthException($"the metadata at '{candidate}' has no 'jwks_uri'");
            }

            try
            {
                return _settings.KeySetUrl(document.JwksUri, "jwks_uri");
            }
            catch (PolicyException ex)
            {
                throw new OAuthException($"the metadata at '{candidate}' points at an unusable key set: {ex.Message}");
            }
        }

        throw new OAuthException(
            $"no authorization server metadata at '{candidates[0]}' or '{candidates[1]}'. " +
            "Set 'access.oauth.jwks_uri' if the issuer publishes its keys elsewhere");
    }

    private async Task<IReadOnlyList<SecurityKey>> FetchKeysAsync(Uri uri, CancellationToken cancellationToken)
    {
        var body = await GetAsync(uri, cancellationToken)
                   ?? throw new OAuthException($"'{uri}' answered 404");

        var set = new JsonWebKeySet(body);

        IReadOnlyList<SecurityKey> keys =
        [
            .. set.Keys.Where(key =>
                key.Kty is JsonWebAlgorithmsKeyTypes.RSA or JsonWebAlgorithmsKeyTypes.EllipticCurve &&
                (string.IsNullOrEmpty(key.Use) || key.Use == JsonWebKeyUseNames.Sig) &&
                (string.IsNullOrEmpty(key.Alg) || AccessTokenValidator.Algorithms.Contains(key.Alg))),
        ];

        return keys.Count > 0
            ? keys
            : throw new OAuthException($"the key set at '{uri}' has no RSA or EC signing keys");
    }

    /// <returns>The body, or null on a 404.</returns>
    private async Task<string?> GetAsync(Uri uri, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        HttpResponseMessage response;
        try
        {
            // Buffered by GetAsync, within MaxResponseContentBufferSize.
            response = await _http.GetAsync(uri, cancellationToken);
        }
        catch (HttpRequestException ex) when (ex.HttpRequestError is HttpRequestError.ConfigurationLimitExceeded)
        {
            throw new OAuthException($"'{uri}' sent more than {MaxDocumentBytes} bytes");
        }

        using (response)
        {
            if (response.StatusCode is HttpStatusCode.NotFound)
            {
                return null;
            }

            if (!response.IsSuccessStatusCode)
            {
                throw new OAuthException($"'{uri}' answered {(int)response.StatusCode}");
            }

            return await response.Content.ReadAsStringAsync(cancellationToken);
        }
    }

    /// <remarks>
    /// Everything a fetch can throw that is the remote end's fault or the
    /// network's. A cancellation the caller asked for is not one of them.
    /// </remarks>
    private static bool IsFetchFailure(Exception ex, CancellationToken cancellationToken) =>
        ex is OAuthException or HttpRequestException or JsonException or ArgumentException ||
        (ex is TaskCanceledException && !cancellationToken.IsCancellationRequested);

    private static string Describe(Exception ex) => ex switch
    {
        OAuthException => ex.Message,
        TaskCanceledException => $"no answer within {FetchTimeout.TotalSeconds:0} seconds",
        HttpRequestException => $"the request failed ({ex.Message})",
        _ => "the document is not valid JSON of the expected shape",
    };

    public void Dispose()
    {
        _lifetime.Cancel();
        _http.Dispose();
        _lifetime.Dispose();
    }

    private sealed record KeySnapshot(IReadOnlyList<SecurityKey> Keys, DateTimeOffset FetchedAt)
    {
        public bool Has(string keyId) => Keys.Any(key => key.KeyId == keyId);
    }
}
