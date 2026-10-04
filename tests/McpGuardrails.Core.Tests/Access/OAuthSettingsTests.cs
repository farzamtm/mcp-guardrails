using McpGuardrails.Core.Access;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Access;

/// <summary>Loading and validating the <c>access:</c> section.</summary>
public sealed class OAuthSettingsTests
{
    private const string _base = """
        access:
          oauth:
            issuer: https://login.example.com/tenant/v2.0
            audience: api://mcp-guardrails
        """;

    private static string Rejected(string yaml) =>
        Assert.Throws<PolicyException>(() => PolicyLoader.Parse(yaml)).Message;

    [Fact]
    public void AMinimalBlock_GetsTheDocumentedDefaults()
    {
        var oauth = PolicyLoader.Parse(_base).EffectiveAccess.OAuth!;

        Assert.Equal(new Uri("https://login.example.com/tenant/v2.0"), oauth.IssuerUri);
        Assert.Equal("api://mcp-guardrails", oauth.Audience);
        Assert.Null(oauth.ResourceUri);
        Assert.Null(oauth.JwksUriValue);
        Assert.Empty(oauth.EffectiveRequiredScopes);
        Assert.Equal("sub", oauth.EffectivePrincipalClaim);
        Assert.Equal("groups", oauth.EffectiveGroupsClaim);
        Assert.Equal(TimeSpan.FromSeconds(60), oauth.ClockSkew);
        Assert.Equal(TimeSpan.FromHours(1), oauth.JwksRefresh);
        Assert.Equal(TimeSpan.FromDays(1), oauth.JwksMaxAge);
        Assert.Null(oauth.RequireAtJwt);

        // No required scope: valid, but worth a line in the startup log.
        Assert.Contains("'access.oauth.required_scopes' is empty", Assert.Single(oauth.Warnings), StringComparison.Ordinal);
    }

    [Fact]
    public void EveryOption_IsRead()
    {
        var oauth = PolicyLoader.Parse(_base + """

                resource: https://mcp.example.com/mcp
                jwks_uri: https://login.example.com/keys
                required_scopes: [mcp.tools]
                principal_claim: oid
                groups_claim: roles
                clock_skew_s: 30
                jwks_refresh_s: 600
                jwks_max_age_s: 3600
                require_at_jwt: true
            """).EffectiveAccess.OAuth!;

        Assert.Equal(new Uri("https://mcp.example.com/mcp"), oauth.ResourceUri);
        Assert.Equal(new Uri("https://login.example.com/keys"), oauth.JwksUriValue);
        Assert.Equal(["mcp.tools"], oauth.EffectiveRequiredScopes);
        Assert.Equal("oid", oauth.EffectivePrincipalClaim);
        Assert.Equal("roles", oauth.EffectiveGroupsClaim);
        Assert.Equal(TimeSpan.FromSeconds(30), oauth.ClockSkew);
        Assert.Equal(TimeSpan.FromMinutes(10), oauth.JwksRefresh);
        Assert.Equal(TimeSpan.FromHours(1), oauth.JwksMaxAge);
        Assert.True(oauth.RequireAtJwt);
        Assert.Empty(oauth.Warnings);
    }

    [Fact]
    public void NoAccessSection_MeansNoOAuth()
    {
        Assert.Null(PolicyLoader.Parse("rules: []").EffectiveAccess.OAuth);
        Assert.Same(AccessPolicy.None, PolicyDocument.Empty.EffectiveAccess);
    }

    [Fact]
    public void AnEmptyAccessSection_IsAllowed()
    {
        Assert.Null(PolicyLoader.Parse("access: {}").EffectiveAccess.OAuth);
    }

    [Theory]
    [InlineData("access:\n  oath: {}")]
    [InlineData("access:\n  oauth:\n    issuer: https://a.example\n    audience: x\n    audiance: y")]
    public void AMisspeltKey_IsRefused(string yaml)
    {
        Assert.Contains("not valid", Rejected(yaml), StringComparison.Ordinal);
    }

    [Fact]
    public void TheIssuer_IsRequired()
    {
        Assert.Contains("needs an 'issuer'", Rejected("access:\n  oauth:\n    audience: x"), StringComparison.Ordinal);
    }

    [Fact]
    public void TheAudience_IsRequired()
    {
        var message = Rejected("access:\n  oauth:\n    issuer: https://login.example.com");

        Assert.Contains("needs an 'audience'", message, StringComparison.Ordinal);
        Assert.Contains("any other application", message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("issuer: http://login.example.com", "access.oauth.issuer")]
    [InlineData("issuer: ftp://login.example.com", "access.oauth.issuer")]
    [InlineData("issuer: https://u:p@login.example.com", "access.oauth.issuer")]
    [InlineData("issuer: not-a-url", "access.oauth.issuer")]
    [InlineData("issuer: https://login.example.com\n    jwks_uri: http://keys.example.com", "access.oauth.jwks_uri")]
    public void UnsafeEndpoints_AreRefused(string fields, string setting)
    {
        var yaml = $"access:\n  oauth:\n    {fields}\n    audience: x";
        Assert.Contains(setting, Rejected(yaml), StringComparison.Ordinal);
    }

    [Fact]
    public void LoopbackHttp_NeedsTheOptIn_AndOnlyReachesLoopback()
    {
        const string loopback = "access:\n  oauth:\n    issuer: http://127.0.0.1:9000\n    audience: x";

        Assert.Contains("allow_insecure_localhost", Rejected(loopback), StringComparison.Ordinal);

        var oauth = PolicyLoader.Parse(loopback + "\n    allow_insecure_localhost: true").EffectiveAccess.OAuth!;
        Assert.Equal(new Uri("http://127.0.0.1:9000"), oauth.IssuerUri);

        Assert.Contains(
            "only permits loopback",
            Rejected("access:\n  oauth:\n    issuer: http://login.example.com\n    audience: x\n    allow_insecure_localhost: true"),
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("resource: not-a-url")]
    [InlineData("resource: http://mcp.example.com/mcp")]
    public void ABadResource_IsRefused(string field)
    {
        Assert.Contains("access.oauth.resource", Rejected(_base + "\n    " + field), StringComparison.Ordinal);
    }

    [Fact]
    public void ALoopbackHttpResource_IsAllowed_WithoutTheOptIn()
    {
        // The resource is this proxy's own URL, which clients reach over loopback
        // in the common local setup; it carries no keys.
        var oauth = PolicyLoader.Parse(_base + "\n    resource: http://127.0.0.1:7300/mcp").EffectiveAccess.OAuth!;
        Assert.Equal(new Uri("http://127.0.0.1:7300/mcp"), oauth.ResourceUri);
    }

    [Theory]
    [InlineData("[\"mcp tools\"]")]
    [InlineData("[\"\"]")]
    [InlineData("[\"mcp\\\"tools\"]")]
    [InlineData("[\"mcp\\\\tools\"]")]
    [InlineData("[\"café\"]")]
    [InlineData("[null]")]
    public void ABadScope_IsRefused(string scopes)
    {
        Assert.Contains("single scope names", Rejected(_base + "\n    required_scopes: " + scopes), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("principal_claim: \"\"", "principal_claim")]
    [InlineData("groups_claim: \" \"", "groups_claim")]
    public void AnEmptyClaimName_IsRefused(string field, string setting)
    {
        Assert.Contains(setting, Rejected(_base + "\n    " + field), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("clock_skew_s: -1")]
    [InlineData("clock_skew_s: 301")]
    public void AnOutOfRangeSkew_IsRefused(string field)
    {
        Assert.Contains("clock_skew_s", Rejected(_base + "\n    " + field), StringComparison.Ordinal);
    }

    [Fact]
    public void ARefreshFasterThanAMinute_IsRefused()
    {
        Assert.Contains("jwks_refresh_s", Rejected(_base + "\n    jwks_refresh_s: 59"), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("jwks_max_age_s: 604801")]
    [InlineData("jwks_refresh_s: 7200\n    jwks_max_age_s: 3600")]
    [InlineData("jwks_refresh_s: 90000")]
    public void AMaximumAgeOutOfRange_IsRefused(string fields)
    {
        Assert.Contains("jwks_max_age_s", Rejected(_base + "\n    " + fields), StringComparison.Ordinal);
    }

    [Fact]
    public void TheBoundaries_AreAccepted()
    {
        var oauth = PolicyLoader.Parse(_base + """

                clock_skew_s: 300
                jwks_refresh_s: 60
                jwks_max_age_s: 604800
            """).EffectiveAccess.OAuth!;

        Assert.Equal(TimeSpan.FromDays(7), oauth.JwksMaxAge);
    }
}
