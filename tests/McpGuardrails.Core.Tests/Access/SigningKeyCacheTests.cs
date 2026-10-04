using System.Net;
using McpGuardrails.Core.Access;
using Microsoft.IdentityModel.Tokens;

namespace McpGuardrails.Core.Tests.Access;

/// <summary>
/// _discovery, fetching, refresh, rotation and the maximum age, against a fake
/// authorization server and a hand-moved clock.
/// </summary>
public sealed class SigningKeyCacheTests
{
    private const string _discovery = "/tenant/v2.0/.well-known/openid-configuration";
    private const string _rfc8414 = "/.well-known/oauth-authorization-server/tenant/v2.0";

    // ------------------------------------------------------------- startup

    [Fact]
    public async Task Startup_DiscoversTheKeySetFromTheIssuer()
    {
        var issuer = new TestIssuer();
        using var cache = await issuer.KeysAsync();

        Assert.Equal(new Uri("https://login.example.com" + TestIssuer.JwksPath), cache.JwksUri);
        Assert.Equal(TestIssuer.Now, cache.FetchedAt);

        var keys = await cache.GetKeysAsync("rsa-1");
        Assert.False(keys.IsExpired);
        Assert.Equal(["rsa-1", "ec-1"], keys.Keys!.Select(k => k.KeyId));
    }

    [Fact]
    public async Task Startup_FallsBackToRfc8414Metadata()
    {
        var issuer = new TestIssuer();
        issuer.Handler.Serve(_discovery, "gone", HttpStatusCode.NotFound);
        issuer.Handler.Serve(_rfc8414, TestIssuer.Discovery());

        using var cache = await issuer.KeysAsync();

        Assert.Equal(1, issuer.Handler.Count(_rfc8414));
    }

    [Fact]
    public async Task Startup_WithAConfiguredJwksUri_SkipsDiscovery()
    {
        var issuer = new TestIssuer();
        var settings = TestIssuer.Settings("    jwks_uri: https://keys.example.com/jwks");
        issuer.Handler.Serve("/jwks", TestIssuer.Jwks(issuer.Rsa));

        using var cache = await issuer.KeysAsync(settings);

        Assert.Equal(0, issuer.Handler.Count(_discovery));
        Assert.Equal(new Uri("https://keys.example.com/jwks"), cache.JwksUri);
    }

    [Fact]
    public async Task Startup_WithNoMetadataAnywhere_Fails_NamingBothPlaces()
    {
        var issuer = new TestIssuer();
        issuer.Handler.Serve(_discovery, "gone", HttpStatusCode.NotFound);

        var ex = await Assert.ThrowsAsync<OAuthException>(() => issuer.KeysAsync());

        Assert.Contains("openid-configuration", ex.Message, StringComparison.Ordinal);
        Assert.Contains("oauth-authorization-server", ex.Message, StringComparison.Ordinal);
        Assert.Contains("jwks_uri", ex.Message, StringComparison.Ordinal);
        Assert.Contains("does not start", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Startup_RefusesMetadataNamingAnotherIssuer()
    {
        // The mix-up defence: one server's metadata must not choose another's keys.
        var issuer = new TestIssuer();
        issuer.Handler.Serve(_discovery, TestIssuer.Discovery(issuer: "https://evil.example.com"));

        var ex = await Assert.ThrowsAsync<OAuthException>(() => issuer.KeysAsync());

        Assert.Contains("different issuer", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Startup_RefusesMetadataWithoutAJwksUri()
    {
        var issuer = new TestIssuer();
        issuer.Handler.Serve(_discovery, TestIssuer.Discovery(jwks: null));

        var ex = await Assert.ThrowsAsync<OAuthException>(() => issuer.KeysAsync());

        Assert.Contains("has no 'jwks_uri'", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://login.example.com/keys")]
    [InlineData("https://user:pw@login.example.com/keys")]
    public async Task Startup_RefusesADiscoveredKeySetUrlThatIsNotSafe(string jwks)
    {
        var issuer = new TestIssuer();
        issuer.Handler.Serve(_discovery, TestIssuer.Discovery(jwks: jwks));

        var ex = await Assert.ThrowsAsync<OAuthException>(() => issuer.KeysAsync());

        Assert.Contains("unusable key set", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Startup_RefusesANullMetadataDocument()
    {
        var issuer = new TestIssuer();
        issuer.Handler.Serve(_discovery, "null");

        var ex = await Assert.ThrowsAsync<OAuthException>(() => issuer.KeysAsync());

        Assert.Contains("is not a metadata document", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{not json")]
    [InlineData("[1, 2]")]
    public async Task Startup_RefusesMetadataThatIsNotJson(string body)
    {
        var issuer = new TestIssuer();
        issuer.Handler.Serve(_discovery, body);

        var ex = await Assert.ThrowsAsync<OAuthException>(() => issuer.KeysAsync());

        Assert.Contains("not valid JSON", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Startup_RefusesAKeySetThatIsNotJson()
    {
        var issuer = new TestIssuer();
        issuer.Handler.Serve(TestIssuer.JwksPath, "{not json");

        var ex = await Assert.ThrowsAsync<OAuthException>(() => issuer.KeysAsync());

        Assert.Contains("not valid JSON", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Startup_RefusesAMissingKeySet()
    {
        var issuer = new TestIssuer();
        issuer.Handler.Serve(TestIssuer.JwksPath, "gone", HttpStatusCode.NotFound);

        var ex = await Assert.ThrowsAsync<OAuthException>(() => issuer.KeysAsync());

        Assert.Contains("answered 404", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Startup_RefusesAServerError()
    {
        var issuer = new TestIssuer();
        issuer.Handler.Serve(_discovery, "oops", HttpStatusCode.InternalServerError);

        var ex = await Assert.ThrowsAsync<OAuthException>(() => issuer.KeysAsync());

        Assert.Contains("answered 500", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Startup_RefusesAnOversizedDocument()
    {
        var issuer = new TestIssuer();
        issuer.Handler.Serve(_discovery, new string(' ', SigningKeyCache.MaxDocumentBytes + 1));

        var ex = await Assert.ThrowsAsync<OAuthException>(() => issuer.KeysAsync());

        Assert.Contains("more than", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Startup_ReportsANetworkFailure()
    {
        var issuer = new TestIssuer();
        issuer.Handler.Failure = new HttpRequestException("connection refused");

        var ex = await Assert.ThrowsAsync<OAuthException>(() => issuer.KeysAsync());

        Assert.Contains("the request failed (connection refused)", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Startup_ReportsATimeout()
    {
        var issuer = new TestIssuer();
        issuer.Handler.Failure = new TaskCanceledException("timed out");

        var ex = await Assert.ThrowsAsync<OAuthException>(() => issuer.KeysAsync());

        Assert.Contains("no answer within 10 seconds", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ACancellationMidFetch_IsTheCallers_NotAFetchFailure()
    {
        var issuer = new TestIssuer();
        issuer.Handler.Gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cache = new SigningKeyCache(TestIssuer.Settings(), issuer.Handler, issuer.Clock);
        using var cancelling = new CancellationTokenSource();

        var starting = cache.InitializeAsync(cancelling.Token);
        await cancelling.CancelAsync();

        var thrown = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => starting);
        Assert.IsType<TaskCanceledException>(thrown);
    }

    [Fact]
    public async Task AnExceptionThatIsNoFetchFailure_IsNotDressedUpAsOne()
    {
        // A bug is a bug, not "the issuer is unreachable".
        var issuer = new TestIssuer();
        issuer.Handler.Failure = new InvalidOperationException("bug");

        await Assert.ThrowsAsync<InvalidOperationException>(() => issuer.KeysAsync());
    }

    [Fact]
    public async Task Startup_PropagatesTheCallersOwnCancellation()
    {
        var issuer = new TestIssuer();
        using var cache = new SigningKeyCache(TestIssuer.Settings(), issuer.Handler, issuer.Clock);
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cache.InitializeAsync(cancelled.Token));
    }

    // ------------------------------------------------------ what is trusted

    [Fact]
    public async Task OnlyAsymmetricSignatureKeys_AreKept()
    {
        // A symmetric key in a published set would let anyone mint tokens; an
        // encryption key is not for signatures; an HMAC alg is never accepted.
        var issuer = new TestIssuer();
        var rsa = TestIssuer.Jwk(issuer.Rsa);
        issuer.Handler.Serve(TestIssuer.JwksPath, "{\"keys\": [" +
            "{\"kty\": \"oct\", \"kid\": \"shared\", \"k\": \"c2VjcmV0\"}, " +
            rsa.Replace("\"use\": \"sig\"", "\"use\": \"enc\"", StringComparison.Ordinal).Replace("rsa-1", "enc", StringComparison.Ordinal) + ", " +
            rsa.Replace("\"use\": \"sig\"", "\"alg\": \"HS256\"", StringComparison.Ordinal).Replace("rsa-1", "hs", StringComparison.Ordinal) + ", " +
            rsa.Replace("\"use\": \"sig\"", "\"alg\": \"RS256\"", StringComparison.Ordinal) + ", " +
            TestIssuer.Jwk(issuer.Ec).Replace("\"use\": \"sig\", ", string.Empty, StringComparison.Ordinal) +
            "]}");

        using var cache = await issuer.KeysAsync();

        var keys = await cache.GetKeysAsync(null);
        Assert.Equal(["rsa-1", "ec-1"], keys.Keys!.Select(k => k.KeyId));
    }

    [Fact]
    public async Task AKeySetWithNoUsableKeys_IsRefused()
    {
        var issuer = new TestIssuer();
        issuer.Handler.Serve(TestIssuer.JwksPath, """{"keys": [{"kty": "oct", "k": "c2VjcmV0"}]}""");

        var ex = await Assert.ThrowsAsync<OAuthException>(() => issuer.KeysAsync());

        Assert.Contains("no RSA or EC signing keys", ex.Message, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------- refresh

    [Fact]
    public async Task Keys_AreNotRefetched_BeforeTheRefreshInterval()
    {
        var issuer = new TestIssuer();
        using var cache = await issuer.KeysAsync();

        issuer.Clock.Advance(TimeSpan.FromMinutes(59));
        await cache.GetKeysAsync("rsa-1");

        Assert.Equal(1, issuer.Handler.Count(TestIssuer.JwksPath));
    }

    [Fact]
    public async Task Keys_AreRefetched_OnceTheRefreshIntervalPasses()
    {
        var issuer = new TestIssuer();
        using var cache = await issuer.KeysAsync();
        issuer.Handler.Serve(TestIssuer.JwksPath, TestIssuer.Jwks(issuer.Ec));

        issuer.Clock.Advance(TimeSpan.FromHours(1));
        var keys = await cache.GetKeysAsync("ec-1");

        Assert.Equal(2, issuer.Handler.Count(TestIssuer.JwksPath));
        Assert.Equal(["ec-1"], keys.Keys!.Select(k => k.KeyId));
        Assert.Equal(issuer.Clock.Now, cache.FetchedAt);
    }

    [Fact]
    public async Task AnUnknownKeyId_TriggersARefetch_ForKeyRotation()
    {
        var issuer = new TestIssuer();
        using var cache = await issuer.KeysAsync();
        var rotated = new RsaSecurityKey(System.Security.Cryptography.RSA.Create(2048)) { KeyId = "rsa-2" };
        issuer.Handler.Serve(TestIssuer.JwksPath, TestIssuer.Jwks(issuer.Rsa, rotated));

        issuer.Clock.Advance(SigningKeyCache.RetryCooldown);
        var keys = await cache.GetKeysAsync("rsa-2");

        Assert.Contains("rsa-2", keys.Keys!.Select(k => k.KeyId));
    }

    [Fact]
    public async Task UnknownKeyIds_AreRateLimited()
    {
        // A stream of tokens with made-up key ids must not become a stream of
        // requests to the authorization server.
        var issuer = new TestIssuer();
        using var cache = await issuer.KeysAsync();

        for (var i = 0; i < 20; i++)
        {
            await cache.GetKeysAsync($"made-up-{i}");
        }

        Assert.Equal(1, issuer.Handler.Count(TestIssuer.JwksPath));

        issuer.Clock.Advance(SigningKeyCache.RetryCooldown);
        await cache.GetKeysAsync("made-up-again");
        await cache.GetKeysAsync("and-again");

        Assert.Equal(2, issuer.Handler.Count(TestIssuer.JwksPath));
    }

    [Fact]
    public async Task AFailedRefresh_KeepsTheOldKeys_UntilTheMaximumAge()
    {
        var issuer = new TestIssuer();
        using var cache = await issuer.KeysAsync();
        issuer.Handler.Failure = new HttpRequestException("down");

        issuer.Clock.Advance(TimeSpan.FromHours(23));
        var keys = await cache.GetKeysAsync("rsa-1");

        Assert.False(keys.IsExpired);
        Assert.Equal(TestIssuer.Now, cache.FetchedAt);
    }

    [Fact]
    public async Task PastTheMaximumAge_NoKeysAreTrusted()
    {
        var issuer = new TestIssuer();
        using var cache = await issuer.KeysAsync();
        issuer.Handler.Failure = new HttpRequestException("down");

        issuer.Clock.Advance(TimeSpan.FromHours(24) + TimeSpan.FromSeconds(1));
        var keys = await cache.GetKeysAsync("rsa-1");

        Assert.True(keys.IsExpired);
        Assert.Null(keys.Keys);
    }

    [Fact]
    public async Task AFailedRefresh_IsRetried_AfterTheCooldown_AndRecovers()
    {
        var issuer = new TestIssuer();
        using var cache = await issuer.KeysAsync();
        issuer.Handler.Failure = new HttpRequestException("down");

        issuer.Clock.Advance(TimeSpan.FromHours(1));
        await cache.GetKeysAsync("rsa-1");
        await cache.GetKeysAsync("rsa-1");
        Assert.Equal(2, issuer.Handler.Count(TestIssuer.JwksPath));

        issuer.Handler.Failure = null;
        issuer.Clock.Advance(SigningKeyCache.RetryCooldown);
        await cache.GetKeysAsync("rsa-1");

        Assert.Equal(3, issuer.Handler.Count(TestIssuer.JwksPath));
        Assert.Equal(issuer.Clock.Now, cache.FetchedAt);
    }

    [Fact]
    public async Task ARequestDuringARefresh_UsesTheKeysThereAre()
    {
        var issuer = new TestIssuer();
        using var cache = await issuer.KeysAsync();
        issuer.Clock.Advance(TimeSpan.FromHours(1));
        issuer.Handler.Gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var refreshing = cache.GetKeysAsync("rsa-1").AsTask();
        var startedAt = issuer.Clock.Now;

        // Past the cooldown, so this request would refresh too if it could.
        issuer.Clock.Advance(SigningKeyCache.RetryCooldown);
        var meanwhile = await cache.GetKeysAsync("rsa-1");

        Assert.False(meanwhile.IsExpired);
        Assert.Equal(TestIssuer.Now, cache.FetchedAt);
        Assert.Equal(2, issuer.Handler.Count(TestIssuer.JwksPath));

        issuer.Handler.Gate.SetResult();
        await refreshing;
        Assert.Equal(startedAt, cache.FetchedAt);
    }

    [Fact]
    public async Task LookingUpKeys_BeforeStartup_IsAProgrammingError()
    {
        var issuer = new TestIssuer();
        using var cache = new SigningKeyCache(TestIssuer.Settings(), issuer.Handler, issuer.Clock);

        await Assert.ThrowsAsync<InvalidOperationException>(() => cache.GetKeysAsync(null).AsTask());
        Assert.Null(cache.FetchedAt);
        Assert.Null(cache.JwksUri);
    }

    [Fact]
    public void TheProductionHandler_FollowsNoRedirects()
    {
        using var handler = SigningKeyCache.CreateHandler();
        Assert.False(handler.AllowAutoRedirect);
    }

    [Fact]
    public void TheCache_RejectsNullArguments()
    {
        using var handler = new IssuerHandler();
        Assert.Throws<ArgumentNullException>(() => new SigningKeyCache(null!, handler));
        Assert.Throws<ArgumentNullException>(() => new SigningKeyCache(TestIssuer.Settings(), null!));

        // The system clock and a null logger when none are given.
        using var cache = new SigningKeyCache(TestIssuer.Settings(), handler);
        Assert.Null(cache.FetchedAt);
    }
}
