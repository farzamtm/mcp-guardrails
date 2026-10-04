using McpGuardrails.Core.Upstream;
using McpGuardrails.Core.UpstreamAuth;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Authentication;
using ModelContextProtocol.Client;

namespace McpGuardrails.Core.Tests.UpstreamAuth;

public sealed class UpstreamOAuthTests
{
    private static readonly Uri _url = new("https://mcp.example.com/mcp");

    private static UpstreamServerConfig Remote(UpstreamOAuthSettings? oauth = null) => new()
    {
        Name = "linear",
        Transport = UpstreamTransport.Http,
        Url = _url,
        OAuth = oauth ?? new UpstreamOAuthSettings([]),
    };

    private static MemoryTokenStore LoggedIn(Uri? url = null)
    {
        var store = new MemoryTokenStore();
        new StoredTokenCache(store, "linear", url ?? _url)
            .StoreTokensAsync(new TokenContainer { TokenType = "Bearer", AccessToken = "a", RefreshToken = "r", ObtainedAt = DateTimeOffset.UnixEpoch })
            .AsTask().GetAwaiter().GetResult();
        return store;
    }

    // ------------------------------------------------------------- serving

    [Fact]
    public void Serving_WithAStoredLogin_UsesItSilently()
    {
        var options = UpstreamOAuth.ForServing(Remote(new UpstreamOAuthSettings(["read"], "client-1")), LoggedIn());

        Assert.IsType<StoredTokenCache>(options.TokenCache);
        Assert.Equal(["read"], options.Scopes);
        Assert.Equal("client-1", options.ClientId);
    }

    [Fact]
    public void Serving_WithNoScopesConfigured_LeavesThemToTheServer()
    {
        Assert.Null(UpstreamOAuth.ForServing(Remote(), LoggedIn()).Scopes);
    }

    [Fact]
    public async Task Serving_NeverAsksAPerson()
    {
        var options = UpstreamOAuth.ForServing(Remote(), LoggedIn());

        var ex = await Assert.ThrowsAsync<UpstreamLoginRequiredException>(
            () => options.AuthorizationCallbackHandler!(
                new AuthorizationCallbackContext { AuthorizationUri = _url, RedirectUri = _url }, CancellationToken.None));

        Assert.Equal("linear", ex.Server);
        Assert.Contains("needs a new login", ex.Message, StringComparison.Ordinal);
        Assert.Contains("run 'mcp-guardrails auth login linear'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Serving_WithoutALogin_FailsBeforeConnecting()
    {
        var ex = Assert.Throws<UpstreamLoginRequiredException>(() => UpstreamOAuth.ForServing(Remote(), new MemoryTokenStore()));
        Assert.Contains("has never been logged in", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Serving_WithALoginForAnotherUrl_FailsBeforeConnecting()
    {
        var ex = Assert.Throws<UpstreamLoginRequiredException>(
            () => UpstreamOAuth.ForServing(Remote(), LoggedIn(new Uri("https://old.example.com/mcp"))));
        Assert.Contains("at a different URL", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Serving_WithAnUnreadableLogin_FailsBeforeConnecting()
    {
        var store = new MemoryTokenStore { Items = { ["linear"] = "garbage" } };

        var ex = Assert.Throws<UpstreamLoginRequiredException>(() => UpstreamOAuth.ForServing(Remote(), store));
        Assert.Contains("cannot read", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ServingTransports_GiveOAuthOnlyToServersThatUseIt()
    {
        var factory = UpstreamOAuth.ServingTransports(LoggedIn());

        var remote = factory(Remote(), NullLoggerFactory.Instance);
        var plain = factory(Remote() with { OAuth = null }, NullLoggerFactory.Instance);

        Assert.IsType<HttpClientTransport>(remote);
        Assert.IsType<HttpClientTransport>(plain);
        Assert.Throws<UpstreamLoginRequiredException>(
            () => UpstreamOAuth.ServingTransports(new MemoryTokenStore())(Remote(), NullLoggerFactory.Instance));
    }

    // --------------------------------------------------------------- login

    [Fact]
    public async Task Login_StartsFresh_AndRegistersDynamically()
    {
        var store = LoggedIn();
        var redirect = new Uri("http://127.0.0.1:5000/callback");
        Func<AuthorizationCallbackContext, CancellationToken, Task<AuthorizationResult?>> authorize =
            (_, _) => Task.FromResult<AuthorizationResult?>(null);

        var options = UpstreamOAuth.ForLogin(Remote(new UpstreamOAuthSettings(["write"])), store, redirect, authorize);

        Assert.Equal(redirect, options.RedirectUri);
        Assert.Same(authorize, options.AuthorizationCallbackHandler);
        Assert.Equal(["write"], options.Scopes);
        Assert.Equal("mcp-guardrails", options.DynamicClientRegistration!.ClientName);
        Assert.Null(await options.TokenCache!.GetTokensAsync(CancellationToken.None));
        Assert.Null(UpstreamOAuth.ForLogin(Remote(), store, redirect, authorize).Scopes);
    }

    [Fact]
    public void BothBuilders_RejectAServerWithoutOAuth_AndNulls()
    {
        var plain = Remote() with { OAuth = null };
        var store = new MemoryTokenStore();
        var redirect = new Uri("http://127.0.0.1/callback");
        Func<AuthorizationCallbackContext, CancellationToken, Task<AuthorizationResult?>> authorize =
            (_, _) => Task.FromResult<AuthorizationResult?>(null);

        Assert.Throws<ArgumentException>(() => UpstreamOAuth.ForServing(plain, store));
        Assert.Throws<ArgumentException>(() => UpstreamOAuth.ForLogin(plain, store, redirect, authorize));
        Assert.Throws<ArgumentNullException>(() => UpstreamOAuth.ForServing(null!, store));
        Assert.Throws<ArgumentNullException>(() => UpstreamOAuth.ForServing(Remote(), null!));
        Assert.Throws<ArgumentNullException>(() => UpstreamOAuth.ForLogin(null!, store, redirect, authorize));
        Assert.Throws<ArgumentNullException>(() => UpstreamOAuth.ForLogin(Remote(), null!, redirect, authorize));
        Assert.Throws<ArgumentNullException>(() => UpstreamOAuth.ForLogin(Remote(), store, null!, authorize));
        Assert.Throws<ArgumentNullException>(() => UpstreamOAuth.ForLogin(Remote(), store, redirect, null!));
        Assert.Throws<ArgumentNullException>(() => UpstreamOAuth.ServingTransports(null!));
    }

    // ------------------------------------------------------- recognising it

    [Fact]
    public void ALoginRequirement_IsFoundHoweverDeeplyWrapped()
    {
        var login = new UpstreamLoginRequiredException("linear", "x");

        Assert.Same(login, UpstreamOAuth.LoginRequired(login));
        Assert.Same(login, UpstreamOAuth.LoginRequired(new HttpRequestException("outer", new InvalidOperationException("mid", login))));
        Assert.Same(login, UpstreamOAuth.LoginRequired(new AggregateException(new InvalidOperationException(), login)));
        Assert.Null(UpstreamOAuth.LoginRequired(new AggregateException(new InvalidOperationException())));
        Assert.Null(UpstreamOAuth.LoginRequired(new InvalidOperationException()));
        Assert.Null(UpstreamOAuth.LoginRequired(null));
    }
}
