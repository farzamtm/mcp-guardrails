using System.Net;
using System.Security.Cryptography;
using System.Text;
using McpGuardrails.Core.Access;
using McpGuardrails.Core.Policy;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace McpGuardrails.Core.Tests.Access;

/// <summary>
/// An authorization server in a test: real keys, real signed tokens, and the
/// metadata and key set documents served through a fake transport.
/// </summary>
internal sealed class TestIssuer
{
    public const string Issuer = "https://login.example.com/tenant/v2.0";
    public const string Audience = "api://mcp-guardrails";
    public const string JwksPath = "/tenant/keys";

    public static readonly DateTimeOffset Now = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);

    public TestIssuer()
    {
        Rsa = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "rsa-1" };
        Ec = new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256)) { KeyId = "ec-1" };
        Handler = new IssuerHandler();
        Handler.Serve("/tenant/v2.0/.well-known/openid-configuration", Discovery());
        Handler.Serve(JwksPath, Jwks(Rsa, Ec));
    }

    public RsaSecurityKey Rsa { get; }

    public ECDsaSecurityKey Ec { get; }

    public IssuerHandler Handler { get; }

    public ManualClock Clock { get; } = new(Now);

    public static OAuthSettings Settings(string extra = "") =>
        PolicyLoader.Parse($"""
            access:
              oauth:
                issuer: {Issuer}
                audience: {Audience}
            {extra}
            """).EffectiveAccess.OAuth!;

    public static string Discovery(string issuer = Issuer, string? jwks = "https://login.example.com" + JwksPath) =>
        jwks is null
            ? $$"""{"issuer": "{{issuer}}"}"""
            : $$"""{"issuer": "{{issuer}}", "jwks_uri": "{{jwks}}"}""";

    public static string Jwks(params SecurityKey[] keys) =>
        "{\"keys\": [" + string.Join(", ", keys.Select(Jwk)) + "]}";

    public static string Jwk(SecurityKey key) => key switch
    {
        RsaSecurityKey rsa => RsaJwk(rsa),
        ECDsaSecurityKey ec => EcJwk(ec),
        _ => throw new ArgumentException("unsupported key", nameof(key)),
    };

    private static string RsaJwk(RsaSecurityKey key)
    {
        var p = key.Rsa.ExportParameters(false);
        return $$"""{"kty": "RSA", "kid": "{{key.KeyId}}", "use": "sig", "n": "{{Base64UrlEncoder.Encode(p.Modulus)}}", "e": "{{Base64UrlEncoder.Encode(p.Exponent)}}"}""";
    }

    private static string EcJwk(ECDsaSecurityKey key)
    {
        var p = key.ECDsa.ExportParameters(false);
        return $$"""{"kty": "EC", "kid": "{{key.KeyId}}", "use": "sig", "crv": "P-256", "x": "{{Base64UrlEncoder.Encode(p.Q.X)}}", "y": "{{Base64UrlEncoder.Encode(p.Q.Y)}}"}""";
    }

    public async Task<SigningKeyCache> KeysAsync(OAuthSettings? settings = null)
    {
        var cache = new SigningKeyCache(settings ?? Settings(), Handler, Clock);
        await cache.InitializeAsync();
        return cache;
    }

    public async Task<AccessTokenValidator> ValidatorAsync(OAuthSettings? settings = null)
    {
        settings ??= Settings();
        return new AccessTokenValidator(settings, await KeysAsync(settings), Clock);
    }

    /// <summary>A signed token; every part overridable.</summary>
    public string Token(
        string? subject = "alice",
        string issuer = Issuer,
        string audience = Audience,
        SecurityKey? key = null,
        string? algorithm = null,
        TimeSpan? expiresIn = null,
        bool noExpiry = false,
        DateTimeOffset? notBefore = null,
        IDictionary<string, object>? claims = null,
        string? type = null)
    {
        key ??= Rsa;
        var payload = new Dictionary<string, object>(claims ?? new Dictionary<string, object>());

        if (subject is not null)
        {
            payload["sub"] = subject;
        }

        if (!noExpiry)
        {
            payload["exp"] = (Now + (expiresIn ?? TimeSpan.FromMinutes(5))).ToUnixTimeSeconds();
        }

        if (notBefore is { } nbf)
        {
            payload["nbf"] = nbf.ToUnixTimeSeconds();
        }

        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Claims = payload,
            TokenType = type,
            SigningCredentials = new SigningCredentials(
                key, algorithm ?? (key is ECDsaSecurityKey ? SecurityAlgorithms.EcdsaSha256 : SecurityAlgorithms.RsaSha256)),
        });
    }

    /// <summary>A token with a hand-written header and no valid signature.</summary>
    public static string Unsigned(string header, string payload, string signature = "") =>
        $"{Base64UrlEncoder.Encode(header)}.{Base64UrlEncoder.Encode(payload)}.{signature}";

    /// <summary>HS256 over the given bytes, used as if they were a shared secret.</summary>
    public static string Hmac(byte[] secret, string payload)
    {
        var signingInput = $"{Base64UrlEncoder.Encode("""{"alg":"HS256","typ":"JWT","kid":"rsa-1"}""")}.{Base64UrlEncoder.Encode(payload)}";
        var signature = HMACSHA256.HashData(secret, Encoding.ASCII.GetBytes(signingInput));
        return $"{signingInput}.{Base64UrlEncoder.Encode(signature)}";
    }
}

/// <summary>Serves fixed documents by path, counts requests, fails on demand.</summary>
internal sealed class IssuerHandler : HttpMessageHandler
{
    private readonly Dictionary<string, (HttpStatusCode Status, string Body)> _routes = new(StringComparer.Ordinal);

    public Dictionary<string, int> Requests { get; } = new(StringComparer.Ordinal);

    /// <summary>When set, every request throws this instead of being answered.</summary>
    public Exception? Failure { get; set; }

    /// <summary>When set, awaited before answering.</summary>
    public TaskCompletionSource? Gate { get; set; }

    public void Serve(string path, string body, HttpStatusCode status = HttpStatusCode.OK) =>
        _routes[path] = (status, body);

    public int Count(string path)
    {
        lock (Requests)
        {
            return Requests.GetValueOrDefault(path);
        }
    }

    /// <summary>Waits until <paramref name="path"/> has been requested <paramref name="count"/> times.</summary>
    public async Task WaitForAsync(string path, int count)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        while (Count(path) < count)
        {
            await Task.Delay(5, timeout.Token);
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsolutePath;

        lock (Requests)
        {
            Requests[path] = Requests.GetValueOrDefault(path) + 1;
        }

        if (Gate is { } gate)
        {
            await gate.Task.WaitAsync(cancellationToken);
        }

        if (Failure is { } failure)
        {
            throw failure;
        }

        return _routes.TryGetValue(path, out var route)
            ? new HttpResponseMessage(route.Status) { Content = new StringContent(route.Body) }
            : new HttpResponseMessage(HttpStatusCode.NotFound);
    }
}

/// <summary>A clock the test moves by hand.</summary>
internal sealed class ManualClock(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;

    public override DateTimeOffset GetUtcNow() => Now;

    public void Advance(TimeSpan by) => Now += by;
}
