using System.Security.Cryptography;
using McpGuardrails.Core.Access;
using Microsoft.IdentityModel.Tokens;

namespace McpGuardrails.Core.Tests.Access;

/// <summary>
/// Every way a token can be wrong, with real keys and real signatures.
/// </summary>
public sealed class AccessTokenValidatorTests
{
    private static readonly string _payload =
        $$"""{"iss": "{{TestIssuer.Issuer}}", "aud": "{{TestIssuer.Audience}}", "sub": "mallory", "exp": {{TestIssuer.Now.AddMinutes(5).ToUnixTimeSeconds()}}}""";

    private static async Task<TokenCheck> Check(TestIssuer issuer, string token, string extra = "") =>
        await (await issuer.ValidatorAsync(TestIssuer.Settings(extra))).ValidateAsync(token);

    // ---------------------------------------------------------------- valid

    [Fact]
    public async Task AGoodRsaToken_IsValid_AndNamesThePrincipal()
    {
        var issuer = new TestIssuer();

        var check = await Check(issuer, issuer.Token());

        Assert.Equal(TokenStatus.Valid, check.Status);
        Assert.Equal("alice", check.Caller!.Principal);
        Assert.Empty(check.Caller.Groups);
        Assert.Null(check.Problem);
    }

    [Fact]
    public async Task AGoodEcToken_IsValid()
    {
        var issuer = new TestIssuer();

        var check = await Check(issuer, issuer.Token(key: issuer.Ec));

        Assert.Equal(TokenStatus.Valid, check.Status);
    }

    [Fact]
    public async Task ATokenWithoutAKeyId_IsCheckedAgainstEveryKey()
    {
        var issuer = new TestIssuer();
        var anonymous = new RsaSecurityKey(issuer.Rsa.Rsa);

        var check = await Check(issuer, issuer.Token(key: anonymous));

        Assert.Equal(TokenStatus.Valid, check.Status);
    }

    [Fact]
    public async Task ThePrincipalAndGroupsClaims_AreConfigurable()
    {
        var issuer = new TestIssuer();
        var token = issuer.Token(claims: new Dictionary<string, object>
        {
            ["preferred_username"] = "alice@example.com",
            ["roles"] = new[] { "admins", "engineering" },
        });

        var check = await Check(issuer, token, "    principal_claim: preferred_username\n    groups_claim: roles");

        Assert.Equal("alice@example.com", check.Caller!.Principal);
        Assert.Equal(["admins", "engineering"], check.Caller.Groups);
    }

    [Fact]
    public async Task GroupsFromTheDefaultClaim_AreCarried()
    {
        var issuer = new TestIssuer();
        var token = issuer.Token(claims: new Dictionary<string, object> { ["groups"] = new[] { "ops" } });

        var check = await Check(issuer, token);

        Assert.Equal(["ops"], check.Caller!.Groups);
    }

    // ------------------------------------------------------------- forgeries

    [Fact]
    public async Task AlgNone_IsRefused()
    {
        var issuer = new TestIssuer();

        var check = await Check(issuer, TestIssuer.Unsigned("""{"alg":"none","typ":"JWT"}""", _payload));

        Assert.Equal(TokenStatus.Invalid, check.Status);
        Assert.Null(check.Caller);
    }

    [Fact]
    public async Task HmacSignedWithThePublicKey_IsRefused()
    {
        // The classic key-confusion attack: the attacker knows the public key
        // and hopes the verifier treats it as an HMAC secret.
        var issuer = new TestIssuer();
        var publicKey = issuer.Rsa.Rsa.ExportSubjectPublicKeyInfo();

        var check = await Check(issuer, TestIssuer.Hmac(publicKey, _payload));

        Assert.Equal(TokenStatus.Invalid, check.Status);
        Assert.Null(check.Caller);
    }

    [Fact]
    public async Task ATokenSignedByAnotherKey_IsRefused()
    {
        var issuer = new TestIssuer();
        var stranger = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "rsa-1" };

        var check = await Check(issuer, issuer.Token(key: stranger));

        Assert.Equal(TokenStatus.Invalid, check.Status);
        Assert.Equal("invalid signature", check.Problem);
    }

    [Fact]
    public async Task ATamperedPayload_IsRefused()
    {
        var issuer = new TestIssuer();
        var parts = issuer.Token().Split('.');
        var forged = $"{parts[0]}.{Base64UrlEncoder.Encode(_payload)}.{parts[2]}";

        var check = await Check(issuer, forged);

        Assert.Equal("invalid signature", check.Problem);
    }

    [Fact]
    public async Task AnAcceptedAsymmetricAlgorithmOutsideTheDefaults_IsStillValid()
    {
        var issuer = new TestIssuer();

        var check = await Check(issuer, issuer.Token(algorithm: SecurityAlgorithms.RsaSsaPssSha256));

        Assert.Equal(TokenStatus.Valid, check.Status);
    }

    // --------------------------------------------------------- wrong target

    [Fact]
    public async Task ATokenFromAnotherIssuer_IsRefused()
    {
        var issuer = new TestIssuer();

        var check = await Check(issuer, issuer.Token(issuer: "https://evil.example.com"));

        Assert.Equal("token from another issuer", check.Problem);
    }

    [Fact]
    public async Task ATokenForAnotherAudience_IsRefused()
    {
        // The confused deputy: a real token from the right issuer, minted for a
        // different application.
        var issuer = new TestIssuer();

        var check = await Check(issuer, issuer.Token(audience: "api://some-other-app"));

        Assert.Equal("token not meant for this proxy", check.Problem);
    }

    // -------------------------------------------------------------- lifetime

    [Fact]
    public async Task ATokenWithNoExpiry_IsRefused()
    {
        var issuer = new TestIssuer();

        var check = await Check(issuer, issuer.Token(noExpiry: true));

        Assert.Equal("token has no expiry", check.Problem);
    }

    [Fact]
    public async Task AnExpiredToken_IsRefused_OnceTheSkewIsUsedUp()
    {
        var issuer = new TestIssuer();
        var validator = await issuer.ValidatorAsync();
        var token = issuer.Token(expiresIn: TimeSpan.FromMinutes(-1));

        // One minute past exp, within the default 60-second skew.
        Assert.Equal(TokenStatus.Valid, (await validator.ValidateAsync(token)).Status);

        issuer.Clock.Advance(TimeSpan.FromSeconds(1));
        var check = await validator.ValidateAsync(token);

        Assert.Equal("token expired", check.Problem);
    }

    [Fact]
    public async Task ATokenNotYetValid_IsRefused_BeyondTheSkew()
    {
        var issuer = new TestIssuer();
        var validator = await issuer.ValidatorAsync();

        Assert.Equal(
            TokenStatus.Valid,
            (await validator.ValidateAsync(issuer.Token(notBefore: TestIssuer.Now.AddSeconds(60)))).Status);

        var check = await validator.ValidateAsync(issuer.Token(notBefore: TestIssuer.Now.AddSeconds(61)));

        Assert.Equal("token not yet valid", check.Problem);
    }

    [Fact]
    public async Task ZeroSkew_MeansExactly()
    {
        var issuer = new TestIssuer();

        var check = await Check(issuer, issuer.Token(expiresIn: TimeSpan.FromSeconds(-1)), "    clock_skew_s: 0");

        Assert.Equal("token expired", check.Problem);
    }

    // ------------------------------------------------------------- principal

    [Fact]
    public async Task ATokenWithoutThePrincipalClaim_IsRefused()
    {
        var issuer = new TestIssuer();

        var check = await Check(issuer, issuer.Token(subject: null));

        Assert.Equal("no usable principal claim", check.Problem);
    }

    [Theory]
    [InlineData("   ")]
    [InlineData("alice\nadmin")]
    public async Task APrincipalThatCannotBeLoggedSafely_IsRefused(string subject)
    {
        var issuer = new TestIssuer();

        var check = await Check(issuer, issuer.Token(subject: subject));

        Assert.Equal("no usable principal claim", check.Problem);
    }

    [Fact]
    public async Task AnOverlongPrincipal_IsRefused()
    {
        var issuer = new TestIssuer();

        var check = await Check(issuer, issuer.Token(subject: new string('a', AccessTokenValidator.MaxPrincipalLength + 1)));

        Assert.Equal("no usable principal claim", check.Problem);
    }

    // ---------------------------------------------------------------- scopes

    [Theory]
    [InlineData("scope", "mcp.tools openid")]
    [InlineData("scp", "openid mcp.tools")]
    public async Task RequiredScopes_AreFoundInScopeOrScp(string claim, string value)
    {
        var issuer = new TestIssuer();
        var token = issuer.Token(claims: new Dictionary<string, object> { [claim] = value });

        var check = await Check(issuer, token, "    required_scopes: [mcp.tools]");

        Assert.Equal(TokenStatus.Valid, check.Status);
    }

    [Fact]
    public async Task RequiredScopes_AreFoundInAnArray()
    {
        var issuer = new TestIssuer();
        var token = issuer.Token(claims: new Dictionary<string, object> { ["scp"] = new[] { "mcp.tools", "mcp.admin" } });

        var check = await Check(issuer, token, "    required_scopes: [mcp.tools, mcp.admin]");

        Assert.Equal(TokenStatus.Valid, check.Status);
    }

    [Fact]
    public async Task AMissingScope_IsInsufficientScope_NotInvalid()
    {
        var issuer = new TestIssuer();
        var token = issuer.Token(claims: new Dictionary<string, object> { ["scope"] = "mcp.read" });

        var check = await Check(issuer, token, "    required_scopes: [mcp.tools]");

        Assert.Equal(TokenStatus.InsufficientScope, check.Status);
        Assert.Equal("insufficient scope", check.Problem);
        Assert.Null(check.Caller);
    }

    [Fact]
    public async Task AScopeIsMatchedWhole_NotAsASubstring()
    {
        var issuer = new TestIssuer();
        var token = issuer.Token(claims: new Dictionary<string, object> { ["scope"] = "mcp.toolsx" });

        var check = await Check(issuer, token, "    required_scopes: [mcp.tools]");

        Assert.Equal(TokenStatus.InsufficientScope, check.Status);
    }

    // ------------------------------------------------------------- malformed

    [Theory]
    [InlineData("")]
    [InlineData("not-a-jwt")]
    [InlineData("a.b")]
    [InlineData("!!!.@@@.###")]
    public async Task Garbage_IsMalformed(string token)
    {
        var issuer = new TestIssuer();

        var check = await Check(issuer, token);

        Assert.Equal(TokenStatus.Invalid, check.Status);
        Assert.Equal("malformed token", check.Problem);
    }

    [Fact]
    public async Task AnOversizedToken_IsRefused_BeforeParsing()
    {
        var issuer = new TestIssuer();

        var check = await Check(issuer, new string('a', AccessTokenValidator.MaxTokenLength + 1));

        Assert.Equal("malformed token", check.Problem);
        Assert.Equal(1, issuer.Handler.Count(TestIssuer.JwksPath));
    }

    [Fact]
    public async Task ABadBase64Segment_IsMalformed_NotAnException()
    {
        var issuer = new TestIssuer();
        var token = $"{Base64UrlEncoder.Encode("""{"alg":"RSA-OAEP","enc":"A256GCM"}""")}.a.b.c.d";

        var check = await Check(issuer, token);

        Assert.Equal("malformed token", check.Problem);
    }

    [Fact]
    public async Task AnEncryptedToken_IsInvalid()
    {
        // Five well-formed parts: a JWE. There is no decryption key, so it can
        // never be read, let alone trusted.
        var issuer = new TestIssuer();
        var token = string.Join('.',
            Base64UrlEncoder.Encode("""{"alg":"RSA-OAEP","enc":"A256GCM","kid":"rsa-1"}"""),
            Base64UrlEncoder.Encode("key"),
            Base64UrlEncoder.Encode("iv"),
            Base64UrlEncoder.Encode("ciphertext"),
            Base64UrlEncoder.Encode("tag"));

        var check = await Check(issuer, token);

        Assert.Equal(TokenStatus.Invalid, check.Status);
    }

    // ----------------------------------------------------------- key expiry

    [Fact]
    public async Task KeysPastTheirMaximumAge_MakeEveryTokenUnavailable()
    {
        var issuer = new TestIssuer();
        var validator = await issuer.ValidatorAsync();
        issuer.Handler.Failure = new HttpRequestException("down");
        issuer.Clock.Advance(TimeSpan.FromDays(2));

        var check = await validator.ValidateAsync(issuer.Token(expiresIn: TimeSpan.FromDays(3)));

        Assert.Equal(TokenStatus.Unavailable, check.Status);
    }

    [Fact]
    public async Task TheValidator_RejectsNullArguments()
    {
        var issuer = new TestIssuer();
        using var keys = await issuer.KeysAsync();

        Assert.Throws<ArgumentNullException>(() => new AccessTokenValidator(null!, keys));
        Assert.Throws<ArgumentNullException>(() => new AccessTokenValidator(TestIssuer.Settings(), null!));
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => new AccessTokenValidator(TestIssuer.Settings(), keys).ValidateAsync(null!).AsTask());
    }
}
