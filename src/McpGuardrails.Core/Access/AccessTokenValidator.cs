using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace McpGuardrails.Core.Access;

/// <summary>What validating one access token found.</summary>
public enum TokenStatus
{
    /// <summary>Signed by the issuer, meant for this proxy, current, and granting every required scope.</summary>
    Valid,

    /// <summary>Malformed, forged, expired, for someone else, or naming no principal.</summary>
    Invalid,

    /// <summary>A good token that does not grant every required scope.</summary>
    InsufficientScope,

    /// <summary>The signing keys are too old to trust, so no token can be checked.</summary>
    Unavailable,
}

/// <summary>The outcome of validating one access token.</summary>
/// <param name="Status">The verdict.</param>
/// <param name="Caller">Who the token speaks for, when it is valid.</param>
/// <param name="Problem">
/// Why it is not, as a short fixed phrase safe to send back in a
/// <c>WWW-Authenticate</c> header - never text taken from the token.
/// </param>
public sealed record TokenCheck(TokenStatus Status, CallerIdentity? Caller = null, string? Problem = null)
{
    internal static TokenCheck Invalid(string problem) => new(TokenStatus.Invalid, Problem: problem);
}

/// <summary>
/// Validates JWT access tokens against the configured issuer, audience and
/// scopes.
/// </summary>
/// <remarks>
/// Signature, issuer and audience are checked by Microsoft.IdentityModel, which
/// is what every ASP.NET Core JWT bearer handler runs. Lifetime, scopes and the
/// principal are checked here, against an injectable clock, so every rule below
/// is pinned by a unit test rather than by a library default that could change
/// under an upgrade.
///
/// What is refused, and why each matters:
/// <list type="bullet">
/// <item>Any algorithm outside <see cref="Algorithms"/>: no <c>none</c>, and no
/// HMAC, which would let a public key be used as a shared secret.</item>
/// <item>A token without <c>exp</c>: a token that never expires is a password
/// nobody can rotate.</item>
/// <item>A token without the principal claim: a call nobody can be held to
/// account for would also escape every per-principal budget.</item>
/// <item>A token carrying <c>nonce</c>: that marks an OpenID Connect ID token,
/// which proves a login to a client and is handled far more loosely than an
/// access token (kept in browsers, logged). Where the client and the API share
/// one app registration, its issuer and audience match this proxy's, so
/// without this check a leaked ID token would open every tool.</item>
/// <item>With <c>require_at_jwt</c>, a token whose <c>typ</c> is not
/// <c>at+jwt</c> (RFC 9068). Opt-in, because Entra ID, Okta and Auth0 do not
/// send it by default and would otherwise have every token refused.</item>
/// </list>
/// </remarks>
public sealed class AccessTokenValidator
{
    /// <summary>The longest token accepted, in characters.</summary>
    /// <remarks>
    /// Real access tokens are a few kilobytes at most. The cap bounds the work an
    /// unauthenticated request can cause before any signature is checked.
    /// </remarks>
    public const int MaxTokenLength = 16 * 1024;

    /// <summary>The longest principal accepted, in characters.</summary>
    public const int MaxPrincipalLength = 256;

    /// <summary>The <c>typ</c> values accepted under <c>require_at_jwt</c> (RFC 9068 section 2.1).</summary>
    public static readonly IReadOnlyList<string> AccessTokenTypes = ["at+jwt", "application/at+jwt"];

    /// <summary>The signature algorithms accepted: asymmetric only.</summary>
    public static readonly IReadOnlySet<string> Algorithms = new HashSet<string>(StringComparer.Ordinal)
    {
        SecurityAlgorithms.RsaSha256,
        SecurityAlgorithms.RsaSha384,
        SecurityAlgorithms.RsaSha512,
        SecurityAlgorithms.RsaSsaPssSha256,
        SecurityAlgorithms.RsaSsaPssSha384,
        SecurityAlgorithms.RsaSsaPssSha512,
        SecurityAlgorithms.EcdsaSha256,
        SecurityAlgorithms.EcdsaSha384,
        SecurityAlgorithms.EcdsaSha512,
    };

    private readonly OAuthSettings _settings;
    private readonly SigningKeyCache _keys;
    private readonly TimeProvider _time;
    private readonly JsonWebTokenHandler _handler = new();

    /// <param name="settings">The validated <c>access.oauth</c> block.</param>
    /// <param name="keys">The issuer's signing keys, initialized.</param>
    /// <param name="time">The clock; the system clock when null.</param>
    public AccessTokenValidator(OAuthSettings settings, SigningKeyCache keys, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(keys);

        _settings = settings;
        _keys = keys;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>Validates one bearer token.</summary>
    public async ValueTask<TokenCheck> ValidateAsync(string token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);

        if (token.Length is 0 or > MaxTokenLength)
        {
            return TokenCheck.Invalid("malformed token");
        }

        JsonWebToken parsed;
        try
        {
            parsed = new JsonWebToken(token);
        }
        catch (Exception)
        {
            // Every exception, not a list of them: this parses whatever an
            // unauthenticated client sent, the library throws at least three
            // unrelated types for bad input (a bad base64 segment is a
            // FormatException), and any one that escaped would answer 500 where
            // the request deserves 401.
            return TokenCheck.Invalid("malformed token");
        }

        var keys = await _keys.GetKeysAsync(
            string.IsNullOrEmpty(parsed.Kid) ? null : parsed.Kid, cancellationToken);

        if (keys.IsExpired)
        {
            return new TokenCheck(TokenStatus.Unavailable, Problem: "signing keys unavailable");
        }

        var result = await _handler.ValidateTokenAsync(parsed, new TokenValidationParameters
        {
            ValidIssuer = _settings.Issuer,
            ValidAudience = _settings.Audience,
            IssuerSigningKeys = keys.Keys,
            ValidAlgorithms = Algorithms,
            RequireSignedTokens = true,
            TryAllIssuerSigningKeys = true,
            // Null means "any type", which is the library's default and the
            // only setting most issuers' tokens pass.
            ValidTypes = _settings.RequireAtJwt is true ? AccessTokenTypes : null,
            // Checked below against the injected clock, with the configured skew.
            ValidateLifetime = false,
            RequireExpirationTime = false,
        });

        if (!result.IsValid)
        {
            return TokenCheck.Invalid(Describe(result.Exception));
        }

        if (Lifetime(parsed) is { } lifetimeProblem)
        {
            return TokenCheck.Invalid(lifetimeProblem);
        }

        if (parsed.TryGetClaim(JwtRegisteredClaimNames.Nonce, out _))
        {
            return TokenCheck.Invalid("an ID token, not an access token");
        }

        var identity = result.ClaimsIdentity;
        var principal = identity.FindFirst(_settings.EffectivePrincipalClaim)?.Value;

        if (string.IsNullOrWhiteSpace(principal) ||
            principal.Length > MaxPrincipalLength ||
            principal.Any(char.IsControl))
        {
            return TokenCheck.Invalid("no usable principal claim");
        }

        if (_settings.EffectiveRequiredScopes.Except(Scopes(identity), StringComparer.Ordinal).Any())
        {
            return new TokenCheck(TokenStatus.InsufficientScope, Problem: "insufficient scope");
        }

        return new TokenCheck(
            TokenStatus.Valid,
            new CallerIdentity(
                principal,
                [.. identity.FindAll(_settings.EffectiveGroupsClaim).Select(claim => claim.Value)]));
    }

    private string? Lifetime(JsonWebToken token)
    {
        var now = _time.GetUtcNow();
        var skew = _settings.ClockSkew;

        if (!token.TryGetPayloadValue<long>(JwtRegisteredClaimNames.Exp, out var exp))
        {
            return "token has no expiry";
        }

        if (now > DateTimeOffset.FromUnixTimeSeconds(exp) + skew)
        {
            return "token expired";
        }

        if (token.TryGetPayloadValue<long>(JwtRegisteredClaimNames.Nbf, out var nbf) &&
            DateTimeOffset.FromUnixTimeSeconds(nbf) > now + skew)
        {
            return "token not yet valid";
        }

        return null;
    }

    /// <remarks>
    /// OAuth puts granted scopes in <c>scope</c> as one space-separated string
    /// (RFC 9068). Entra ID uses <c>scp</c>, and some servers send either as a
    /// JSON array, which arrives as one claim per element. All four shapes are
    /// read the same way.
    /// </remarks>
    private static IEnumerable<string> Scopes(ClaimsIdentity identity) =>
        identity.FindAll("scope").Concat(identity.FindAll("scp"))
            .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries));

    /// <remarks>
    /// The exception type, mapped to a fixed phrase. Its message is never used:
    /// it is library text about attacker-supplied input, and it ends up in a
    /// response header.
    /// </remarks>
    private static string Describe(Exception? failure) => failure switch
    {
        SecurityTokenInvalidAudienceException => "token not meant for this proxy",
        SecurityTokenInvalidIssuerException => "token from another issuer",
        SecurityTokenSignatureKeyNotFoundException or SecurityTokenInvalidSignatureException => "invalid signature",
        SecurityTokenInvalidTypeException => "not an access token (typ)",
        _ => "invalid token",
    };
}
