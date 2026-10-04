using McpGuardrails.Core.UpstreamAuth;
using ModelContextProtocol.Authentication;

namespace McpGuardrails.Core.Tests.UpstreamAuth;

/// <summary>A token store that is a dictionary.</summary>
internal sealed class MemoryTokenStore : ITokenStore
{
    public Dictionary<string, string> Items { get; } = new(StringComparer.Ordinal);

    public string Description => "memory";

    public string? Read(string server) => Items.GetValueOrDefault(server);

    public void Write(string server, string secret) => Items[server] = secret;

    public bool Delete(string server) => Items.Remove(server);
}

public sealed class StoredTokenCacheTests
{
    private static readonly Uri _url = new("https://mcp.example.com/mcp");
    private static readonly DateTimeOffset _obtained = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);

    private static TokenContainer Tokens(string? refresh = "refresh-1", int? expiresIn = 3600) => new()
    {
        TokenType = "Bearer",
        AccessToken = "access-1",
        RefreshToken = refresh,
        ExpiresIn = expiresIn,
        Scope = "read write",
        ObtainedAt = _obtained,
        ClientId = "client-1",
        ClientSecret = "client-secret",
        TokenEndpointAuthMethod = "none",
        AuthorizationServer = "https://auth.example.com",
    };

    [Fact]
    public async Task StoredTokens_ComeBackFieldForField()
    {
        var store = new MemoryTokenStore();
        var cache = new StoredTokenCache(store, "linear", _url);

        await cache.StoreTokensAsync(Tokens());
        var back = await new StoredTokenCache(store, "linear", _url).GetTokensAsync();

        Assert.NotNull(back);
        Assert.Equal("Bearer", back.TokenType);
        Assert.Equal("access-1", back.AccessToken);
        Assert.Equal("refresh-1", back.RefreshToken);
        Assert.Equal(3600, back.ExpiresIn);
        Assert.Equal("read write", back.Scope);
        Assert.Equal(_obtained, back.ObtainedAt);
        Assert.Equal("client-1", back.ClientId);
        Assert.Equal("client-secret", back.ClientSecret);
        Assert.Equal("none", back.TokenEndpointAuthMethod);
        Assert.Equal("https://auth.example.com", back.AuthorizationServer);
        Assert.Contains("\"server_url\":\"https://mcp.example.com/mcp\"", store.Items["linear"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task NothingStored_IsNoLogin()
    {
        var cache = new StoredTokenCache(new MemoryTokenStore(), "linear", _url);

        Assert.Null(await cache.GetTokensAsync());
        Assert.Equal(new LoginStatus(LoginState.None), cache.Status());
    }

    [Fact]
    public async Task TokensForAnotherUrl_AreNeverHandedOut()
    {
        // The servers file now points "linear" somewhere else; the old tokens
        // must not follow the name there.
        var store = new MemoryTokenStore();
        await new StoredTokenCache(store, "linear", new Uri("https://mcp.linear.app/mcp")).StoreTokensAsync(Tokens());

        var cache = new StoredTokenCache(store, "linear", new Uri("https://evil.example.com/mcp"));

        Assert.Null(await cache.GetTokensAsync());
        Assert.Equal(LoginState.OtherUrl, cache.Status().State);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("null")]
    [InlineData("{\"access_token\":\"a\",\"token_type\":\"Bearer\"}")]
    [InlineData("{\"server_url\":\"https://mcp.example.com/mcp\",\"token_type\":\"Bearer\"}")]
    [InlineData("{\"server_url\":\"https://mcp.example.com/mcp\",\"access_token\":\"a\"}")]
    public async Task SomethingUnreadable_IsNoLogin(string stored)
    {
        var store = new MemoryTokenStore { Items = { ["linear"] = stored } };
        var cache = new StoredTokenCache(store, "linear", _url);

        Assert.Null(await cache.GetTokensAsync());
        Assert.Equal(LoginState.Unreadable, cache.Status().State);
    }

    [Fact]
    public async Task TheStatus_SaysWhenTheAccessTokenExpires_AndWhetherItRefreshes()
    {
        var store = new MemoryTokenStore();
        await new StoredTokenCache(store, "linear", _url).StoreTokensAsync(Tokens());

        Assert.Equal(
            new LoginStatus(LoginState.LoggedIn, _obtained.AddHours(1), CanRefresh: true),
            new StoredTokenCache(store, "linear", _url).Status());
    }

    [Fact]
    public async Task TheStatus_WithoutExpiryOrRefreshToken()
    {
        var store = new MemoryTokenStore();
        await new StoredTokenCache(store, "linear", _url).StoreTokensAsync(Tokens(refresh: null, expiresIn: null));

        Assert.Equal(new LoginStatus(LoginState.LoggedIn), new StoredTokenCache(store, "linear", _url).Status());
    }

    [Fact]
    public async Task ALoginCache_IgnoresWhatIsStored_UntilItStoresSomething()
    {
        var store = new MemoryTokenStore();
        await new StoredTokenCache(store, "linear", _url).StoreTokensAsync(Tokens());

        var login = new StoredTokenCache(store, "linear", _url, ignoreStored: true);
        Assert.Null(await login.GetTokensAsync());

        await login.StoreTokensAsync(Tokens(refresh: "refresh-2"));
        Assert.Equal("refresh-2", (await login.GetTokensAsync())!.RefreshToken);
    }

    [Fact]
    public async Task TheCache_RejectsNulls()
    {
        var store = new MemoryTokenStore();

        Assert.Throws<ArgumentNullException>(() => new StoredTokenCache(null!, "x", _url));
        Assert.Throws<ArgumentException>(() => new StoredTokenCache(store, " ", _url));
        Assert.Throws<ArgumentNullException>(() => new StoredTokenCache(store, "x", null!));
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => new StoredTokenCache(store, "x", _url).StoreTokensAsync(null!).AsTask());
    }
}
