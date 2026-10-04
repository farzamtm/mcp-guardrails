using System.Text.Json;
using McpGuardrails.Core.Access;
using McpGuardrails.Core.Hosting;

namespace McpGuardrails.Core.Tests.Access;

/// <summary>
/// The protected-resource side of the MCP authorization flow: verdicts,
/// challenges and the metadata document.
/// </summary>
public sealed class OAuthAccessGuardTests
{
    private static readonly Uri _resource = new("http://127.0.0.1:7300/mcp");
    private const string _metadata = "http://127.0.0.1:7300/.well-known/oauth-protected-resource/mcp";

    private static async Task<(TestIssuer Issuer, OAuthAccessGuard Guard)> Guard(string extra = "")
    {
        var issuer = new TestIssuer();
        var settings = TestIssuer.Settings(extra);
        return (issuer, new OAuthAccessGuard(settings, await issuer.ValidatorAsync(settings)));
    }

    // ------------------------------------------------------------- verdicts

    [Fact]
    public async Task AValidToken_IsAllowed_WithItsCaller()
    {
        var (issuer, guard) = await Guard();

        var result = await guard.CheckAsync($"Bearer {issuer.Token()}", origin: null, _resource);

        Assert.Equal(HttpAccessVerdict.Allowed, result.Verdict);
        Assert.Equal("alice", result.Caller!.Principal);
        Assert.Null(result.Challenge);
    }

    [Fact]
    public async Task NoToken_Is401_PointingAtTheMetadata_WithoutAnErrorCode()
    {
        var (_, guard) = await Guard();

        var result = await guard.CheckAsync(null, null, _resource);

        Assert.Equal(HttpAccessVerdict.Unauthorized, result.Verdict);
        Assert.Equal($"Bearer resource_metadata=\"{_metadata}\"", result.Challenge);
    }

    [Fact]
    public async Task AnotherScheme_CountsAsNoToken()
    {
        var (_, guard) = await Guard();

        var result = await guard.CheckAsync("Basic YWxpY2U6c2VjcmV0", null, _resource);

        Assert.Equal(HttpAccessVerdict.Unauthorized, result.Verdict);
        Assert.DoesNotContain("error=", result.Challenge, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ABadToken_Is401_WithInvalidToken()
    {
        var (issuer, guard) = await Guard();

        var result = await guard.CheckAsync(
            $"Bearer {issuer.Token(audience: "api://other")}", null, _resource);

        Assert.Equal(HttpAccessVerdict.Unauthorized, result.Verdict);
        Assert.Equal(
            $"Bearer error=\"invalid_token\", error_description=\"token not meant for this proxy\", resource_metadata=\"{_metadata}\"",
            result.Challenge);
    }

    [Fact]
    public async Task AMissingScope_Is403_NamingTheScopesToAskFor()
    {
        var (issuer, guard) = await Guard("    required_scopes: [mcp.tools, mcp.call]");

        var result = await guard.CheckAsync($"Bearer {issuer.Token()}", null, _resource);

        Assert.Equal(HttpAccessVerdict.InsufficientScope, result.Verdict);
        Assert.Equal(
            $"Bearer error=\"insufficient_scope\", error_description=\"insufficient scope\", scope=\"mcp.tools mcp.call\", resource_metadata=\"{_metadata}\"",
            result.Challenge);
    }

    [Fact]
    public async Task RequiredScopes_AreAdvertised_EvenWithNoToken()
    {
        var (_, guard) = await Guard("    required_scopes: [mcp.tools]");

        var result = await guard.CheckAsync(null, null, _resource);

        Assert.Equal($"Bearer scope=\"mcp.tools\", resource_metadata=\"{_metadata}\"", result.Challenge);
    }

    [Fact]
    public async Task StaleKeys_Are503_WithNoChallenge()
    {
        var (issuer, guard) = await Guard();
        issuer.Handler.Failure = new HttpRequestException("down");
        issuer.Clock.Advance(TimeSpan.FromDays(2));

        var result = await guard.CheckAsync($"Bearer {issuer.Token(expiresIn: TimeSpan.FromDays(3))}", null, _resource);

        Assert.Equal(HttpAccessVerdict.Unavailable, result.Verdict);
        Assert.Null(result.Challenge);
    }

    [Fact]
    public async Task AForeignOrigin_IsForbidden_EvenWithAValidToken()
    {
        var (issuer, guard) = await Guard();

        var result = await guard.CheckAsync($"Bearer {issuer.Token()}", "https://evil.example", _resource);

        Assert.Equal(HttpAccessVerdict.ForbiddenOrigin, result.Verdict);
        Assert.Null(result.Caller);
    }

    [Fact]
    public async Task ALoopbackOrigin_IsAllowedThrough()
    {
        var (issuer, guard) = await Guard();

        var result = await guard.CheckAsync($"Bearer {issuer.Token()}", "http://localhost:6274", _resource);

        Assert.Equal(HttpAccessVerdict.Allowed, result.Verdict);
    }

    // ------------------------------------------------------------- resource

    [Fact]
    public async Task TheResource_IsBuiltFromTheRequest_WhenNotConfigured()
    {
        var (_, guard) = await Guard();

        Assert.Equal(new Uri("http://127.0.0.1:7300/mcp"), guard.Resource("http", "127.0.0.1:7300", "/mcp"));
    }

    [Fact]
    public async Task AHostThatMakesNoUrl_FallsBackToLoopback()
    {
        var (_, guard) = await Guard();

        Assert.Equal(new Uri("http://localhost/mcp"), guard.Resource("http", "bad host\"", "/mcp"));
    }

    [Fact]
    public async Task AConfiguredResource_WinsOverTheRequest()
    {
        var (_, guard) = await Guard("    resource: https://mcp.example.com/mcp");

        Assert.Equal(new Uri("https://mcp.example.com/mcp"), guard.Resource("http", "10.0.0.5:7300", "/mcp"));
    }

    [Theory]
    [InlineData("https://mcp.example.com/mcp", "https://mcp.example.com/.well-known/oauth-protected-resource/mcp")]
    [InlineData("https://mcp.example.com/mcp/", "https://mcp.example.com/.well-known/oauth-protected-resource/mcp")]
    [InlineData("https://mcp.example.com/", "https://mcp.example.com/.well-known/oauth-protected-resource")]
    [InlineData("http://[::1]:7300/mcp", "http://[::1]:7300/.well-known/oauth-protected-resource/mcp")]
    public void TheMetadataUrl_InsertsTheWellKnownPrefix(string resource, string expected)
    {
        Assert.Equal(new Uri(expected), OAuthAccessGuard.MetadataUrl(new Uri(resource)));
    }

    // ------------------------------------------------------------- metadata

    [Fact]
    public async Task TheMetadataDocument_NamesTheResourceAndIssuer()
    {
        var (_, guard) = await Guard("    required_scopes: [mcp.tools]");

        using var json = JsonDocument.Parse(guard.MetadataDocument(_resource));
        var root = json.RootElement;

        Assert.Equal("http://127.0.0.1:7300/mcp", root.GetProperty("resource").GetString());
        Assert.Equal([TestIssuer.Issuer], root.GetProperty("authorization_servers").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["mcp.tools"], root.GetProperty("scopes_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["header"], root.GetProperty("bearer_methods_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal("mcp-guardrails", root.GetProperty("resource_name").GetString());
    }

    [Fact]
    public async Task TheMetadataDocument_OmitsScopes_WhenNoneAreRequired()
    {
        var (_, guard) = await Guard();

        using var json = JsonDocument.Parse(guard.MetadataDocument(_resource));

        Assert.False(json.RootElement.TryGetProperty("scopes_supported", out _));
    }

    [Fact]
    public async Task TheGuard_RejectsNullArguments()
    {
        var (issuer, guard) = await Guard();
        var validator = await issuer.ValidatorAsync();

        Assert.Throws<ArgumentNullException>(() => new OAuthAccessGuard(null!, validator));
        Assert.Throws<ArgumentNullException>(() => new OAuthAccessGuard(TestIssuer.Settings(), null!));
        await Assert.ThrowsAsync<ArgumentNullException>(() => guard.CheckAsync(null, null, null!).AsTask());
        Assert.Throws<ArgumentNullException>(() => OAuthAccessGuard.MetadataUrl(null!));
        Assert.Throws<ArgumentNullException>(() => guard.MetadataDocument(null!));
    }
}
