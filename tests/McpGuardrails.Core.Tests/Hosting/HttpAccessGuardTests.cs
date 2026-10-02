using McpGuardrails.Core.Hosting;

namespace McpGuardrails.Core.Tests.Hosting;

public sealed class HttpAccessGuardTests
{
    private const string _token = "0123456789abcdef0123";

    private static readonly HttpAccessGuard _open = new(bearerToken: null);
    private static readonly HttpAccessGuard _locked = new(_token);

    // ---------------------------------------------------------------- origin

    [Fact]
    public void ARequestWithNoOrigin_IsAllowed()
    {
        // Every non-browser MCP client: no Origin header at all.
        Assert.Equal(HttpAccessVerdict.Allowed, _open.Check(authorization: null, origin: null));
    }

    [Theory]
    [InlineData("http://localhost:3000")]
    [InlineData("http://LOCALHOST")]
    [InlineData("http://127.0.0.1:7300")]
    [InlineData("https://127.0.0.5")]
    [InlineData("http://[::1]:7300")]
    public void ALoopbackOrigin_IsAllowed(string origin)
    {
        Assert.Equal(HttpAccessVerdict.Allowed, _open.Check(null, origin));
    }

    [Theory]
    [InlineData("https://evil.example")]
    [InlineData("http://localhost.evil.example")]
    [InlineData("http://192.168.1.10")]
    [InlineData("null")]
    [InlineData("not a uri")]
    public void AnyOtherOrigin_IsForbidden(string origin)
    {
        // The DNS-rebinding case: someone else's page making the browser POST to
        // the loopback listener.
        Assert.Equal(HttpAccessVerdict.ForbiddenOrigin, _open.Check(null, origin));
    }

    [Fact]
    public void AForeignOrigin_IsForbidden_EvenWithTheRightToken()
    {
        Assert.Equal(HttpAccessVerdict.ForbiddenOrigin, _locked.Check($"Bearer {_token}", "https://evil.example"));
    }

    // ----------------------------------------------------------------- token

    [Theory]
    [InlineData("Bearer " + _token)]
    [InlineData("bearer " + _token)]
    [InlineData("BEARER  " + _token + " ")]
    public void TheRightToken_IsAllowed(string authorization)
    {
        Assert.Equal(HttpAccessVerdict.Allowed, _locked.Check(authorization, null));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(_token)]
    [InlineData("Basic " + _token)]
    [InlineData("Bearer")]
    [InlineData("Bearer wrong")]
    [InlineData("Bearer " + _token + "x")]
    [InlineData("Bearer 0123456789ABCDEF0123")]
    public void AnythingElse_IsUnauthorized_WhenATokenIsRequired(string? authorization)
    {
        Assert.Equal(HttpAccessVerdict.Unauthorized, _locked.Check(authorization, null));
    }

    [Fact]
    public void AnAuthorizationHeader_IsIgnored_WhenNoTokenIsConfigured()
    {
        Assert.Equal(HttpAccessVerdict.Allowed, _open.Check("Bearer anything", null));
    }
}
