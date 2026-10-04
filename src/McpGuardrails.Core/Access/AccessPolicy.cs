using System.Text.Json.Serialization;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Access;

/// <summary>
/// The <c>access:</c> section of a policy file: who may reach the proxy at all.
/// </summary>
/// <remarks>
/// In the policy file rather than on the command line because it is access
/// policy: reviewed and committed beside the rules that key on the identity it
/// produces. Unknown keys are refused, as everywhere a misspelt security option
/// would otherwise be skipped quietly.
/// </remarks>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record AccessPolicy
{
    /// <summary>Nothing configured: the static bearer token, or none on loopback.</summary>
    public static AccessPolicy None { get; } = new();

    /// <summary>JWT access tokens from an external authorization server.</summary>
    [JsonPropertyName("oauth")]
    public OAuthSettings? OAuth { get; init; }

    /// <summary>Validates the section, throwing with a message naming the problem.</summary>
    public void Validate() => OAuth?.Validate();
}

/// <summary>
/// The <c>access.oauth:</c> block: the proxy as an OAuth protected resource.
/// </summary>
/// <remarks>
/// The proxy validates tokens; it never issues them. Everything needed to trust
/// a token - the issuer, the audience that names this proxy, the scopes - is
/// stated here, and nothing is taken from the token itself on trust: the keys
/// come from the issuer configured here, not from a URL the token names.
/// </remarks>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record OAuthSettings
{
    /// <summary>The <c>access.oauth</c> clock skew when unset, in seconds.</summary>
    public const int DefaultClockSkewSeconds = 60;

    /// <summary>The largest clock skew accepted, in seconds.</summary>
    /// <remarks>
    /// Skew stretches every token's lifetime by that much in both directions, so
    /// a large value quietly turns a five-minute token into a fifteen-minute one.
    /// </remarks>
    public const int MaxClockSkewSeconds = 300;

    /// <summary>How often the signing keys are refetched when unset, in seconds.</summary>
    public const int DefaultJwksRefreshSeconds = 3600;

    /// <summary>The shortest refresh interval accepted, in seconds.</summary>
    public const int MinJwksRefreshSeconds = 60;

    /// <summary>How long keys are used without a successful refetch when unset, in seconds.</summary>
    public const int DefaultJwksMaxAgeSeconds = 86_400;

    /// <summary>The longest maximum age accepted, in seconds: a week.</summary>
    public const int MaxJwksMaxAgeSeconds = 7 * 86_400;

    /// <summary>The claim that names the caller when unset.</summary>
    public const string DefaultPrincipalClaim = "sub";

    /// <summary>The claim holding the caller's groups when unset.</summary>
    public const string DefaultGroupsClaim = "groups";

    /// <summary>The authorization server's issuer identifier, exactly as it puts it in <c>iss</c>.</summary>
    [JsonPropertyName("issuer")]
    public string? Issuer { get; init; }

    /// <summary>The <c>aud</c> a token must carry: this proxy's identifier at the authorization server.</summary>
    [JsonPropertyName("audience")]
    public string? Audience { get; init; }

    /// <summary>
    /// The proxy's public MCP endpoint, advertised as the protected resource.
    /// </summary>
    /// <remarks>
    /// Optional. Clients check that the metadata's <c>resource</c> is the URL
    /// they connected to, so behind a reverse proxy this has to be the public
    /// URL; left out, it is built from the request's own scheme and host.
    /// </remarks>
    [JsonPropertyName("resource")]
    public string? Resource { get; init; }

    /// <summary>Scopes every token must grant, all of them.</summary>
    [JsonPropertyName("required_scopes")]
    public IReadOnlyList<string>? RequiredScopes { get; init; }

    /// <summary>The claim whose value is the caller's identity in policy, budgets and the audit log.</summary>
    [JsonPropertyName("principal_claim")]
    public string? PrincipalClaim { get; init; }

    /// <summary>The claim whose values are the caller's groups, matched by a rule's <c>groups:</c>.</summary>
    [JsonPropertyName("groups_claim")]
    public string? GroupsClaim { get; init; }

    /// <summary>Where the signing keys are, when discovery from the issuer is not wanted.</summary>
    [JsonPropertyName("jwks_uri")]
    public string? JwksUri { get; init; }

    /// <summary>Permit plain <c>http://</c> for the issuer and keys, and only to a loopback address.</summary>
    /// <remarks>
    /// For a test authorization server on the same machine. Signing keys fetched
    /// over a network in the clear can be swapped by anyone on the path, and with
    /// them every token, so this never reaches beyond loopback.
    /// </remarks>
    [JsonPropertyName("allow_insecure_localhost")]
    public bool? AllowInsecureLocalhost { get; init; }

    /// <summary>Tolerance for clocks that disagree, applied to <c>exp</c> and <c>nbf</c>.</summary>
    [JsonPropertyName("clock_skew_s")]
    public int? ClockSkewSeconds { get; init; }

    /// <summary>How often the signing keys are refetched.</summary>
    [JsonPropertyName("jwks_refresh_s")]
    public int? JwksRefreshSeconds { get; init; }

    /// <summary>How long the last keys fetched stay usable while the issuer cannot be reached.</summary>
    [JsonPropertyName("jwks_max_age_s")]
    public int? JwksMaxAgeSeconds { get; init; }

    /// <summary>The issuer as a URL. Only meaningful after <see cref="Validate"/>.</summary>
    [JsonIgnore]
    public Uri IssuerUri => new(Issuer!, UriKind.Absolute);

    /// <summary>The configured key set URL, or null to discover it.</summary>
    [JsonIgnore]
    public Uri? JwksUriValue => JwksUri is null ? null : new Uri(JwksUri, UriKind.Absolute);

    /// <summary>The configured resource URL, or null to derive it per request.</summary>
    [JsonIgnore]
    public Uri? ResourceUri => Resource is null ? null : new Uri(Resource, UriKind.Absolute);

    /// <summary>The required scopes, or none.</summary>
    [JsonIgnore]
    public IReadOnlyList<string> EffectiveRequiredScopes => RequiredScopes ?? [];

    /// <summary>The principal claim, defaulting to <c>sub</c>.</summary>
    [JsonIgnore]
    public string EffectivePrincipalClaim => PrincipalClaim ?? DefaultPrincipalClaim;

    /// <summary>The groups claim, defaulting to <c>groups</c>.</summary>
    [JsonIgnore]
    public string EffectiveGroupsClaim => GroupsClaim ?? DefaultGroupsClaim;

    /// <summary>The clock skew.</summary>
    [JsonIgnore]
    public TimeSpan ClockSkew => TimeSpan.FromSeconds(ClockSkewSeconds ?? DefaultClockSkewSeconds);

    /// <summary>The key refresh interval.</summary>
    [JsonIgnore]
    public TimeSpan JwksRefresh => TimeSpan.FromSeconds(JwksRefreshSeconds ?? DefaultJwksRefreshSeconds);

    /// <summary>The key maximum age.</summary>
    [JsonIgnore]
    public TimeSpan JwksMaxAge => TimeSpan.FromSeconds(JwksMaxAgeSeconds ?? DefaultJwksMaxAgeSeconds);

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(Issuer))
        {
            throw new PolicyException("'access.oauth' needs an 'issuer': the authorization server whose tokens are accepted.");
        }

        KeySetUrl(Issuer, "access.oauth.issuer");

        if (JwksUri is not null)
        {
            KeySetUrl(JwksUri, "access.oauth.jwks_uri");
        }

        // Without an audience, a token the same issuer minted for any other
        // application would be accepted here - the confused-deputy case the
        // MCP authorization spec singles out.
        if (string.IsNullOrWhiteSpace(Audience))
        {
            throw new PolicyException(
                "'access.oauth' needs an 'audience': the value a token's 'aud' must hold to be meant " +
                "for this proxy. Without it, tokens issued for any other application would be accepted.");
        }

        if (Resource is not null)
        {
            OutboundUrl.Validate(
                Resource,
                "access.oauth.resource",
                reason: "Clients send their tokens to this URL",
                credentialHint: "clients authenticate with their own tokens",
                allowLoopbackHttp: true);
        }

        foreach (var scope in EffectiveRequiredScopes)
        {
            // RFC 6749 section 3.3's scope-token characters: printable ASCII
            // minus space, '"' and '\'. A space would split into two scopes on
            // the wire, an empty one would be satisfied by nothing (or, depending
            // on the parser, by everything), and a quote would break out of the
            // WWW-Authenticate header the scopes are echoed into.
            if (scope is null || scope.Length == 0 ||
                scope.Any(c => c is < '!' or > '~' or '"' or '\\'))
            {
                throw new PolicyException(
                    "'access.oauth.required_scopes' entries must be single scope names: printable ASCII, " +
                    "no spaces, quotes or backslashes.");
            }
        }

        if (PrincipalClaim is not null && string.IsNullOrWhiteSpace(PrincipalClaim))
        {
            throw new PolicyException("'access.oauth.principal_claim' is empty. Omit it to use 'sub'.");
        }

        if (GroupsClaim is not null && string.IsNullOrWhiteSpace(GroupsClaim))
        {
            throw new PolicyException("'access.oauth.groups_claim' is empty. Omit it to use 'groups'.");
        }

        if (ClockSkewSeconds is < 0 or > MaxClockSkewSeconds)
        {
            throw new PolicyException(
                $"'access.oauth.clock_skew_s' must be between 0 and {MaxClockSkewSeconds} (got {ClockSkewSeconds}).");
        }

        if (JwksRefreshSeconds < MinJwksRefreshSeconds)
        {
            throw new PolicyException(
                $"'access.oauth.jwks_refresh_s' must be at least {MinJwksRefreshSeconds} (got {JwksRefreshSeconds}): " +
                "anything faster asks the authorization server for its keys on every few requests.");
        }

        if (JwksMaxAge > TimeSpan.FromSeconds(MaxJwksMaxAgeSeconds) || JwksMaxAge < JwksRefresh)
        {
            throw new PolicyException(
                $"'access.oauth.jwks_max_age_s' must be between 'jwks_refresh_s' ({(int)JwksRefresh.TotalSeconds}) " +
                $"and {MaxJwksMaxAgeSeconds} (got {(int)JwksMaxAge.TotalSeconds}). Past it, every request is refused " +
                "until the keys can be fetched again.");
        }
    }

    /// <summary>
    /// Checks a URL the signing keys are fetched through - the issuer, a
    /// configured key set, or one named by discovery - throwing a
    /// <see cref="PolicyException"/> naming <paramref name="setting"/> if it is
    /// not safe.
    /// </summary>
    /// <remarks>
    /// One check for all three, so the rules and the advice cannot drift
    /// between a URL the operator wrote and one the issuer's metadata supplied.
    /// </remarks>
    internal Uri KeySetUrl(string value, string setting) =>
        OutboundUrl.Validate(
            value,
            setting,
            reason: "Signing keys fetched in the clear can be replaced by anyone on the path, and with them every token",
            credentialHint: "the keys are public and need no credential",
            allowLoopbackHttp: AllowInsecureLocalhost is true,
            optInSetting: "access.oauth.allow_insecure_localhost");
}
