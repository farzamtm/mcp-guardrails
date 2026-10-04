using System.Text.Json.Serialization;

namespace McpGuardrails.Core.Access;

/// <summary>
/// The two fields this proxy reads from an authorization server's metadata
/// (OpenID Connect Discovery, or RFC 8414).
/// </summary>
/// <remarks>
/// Every other field is ignored rather than refused: this is someone else's
/// document, and it grows.
/// </remarks>
internal sealed record AuthorizationServerDocument
{
    [JsonPropertyName("issuer")]
    public string? Issuer { get; init; }

    [JsonPropertyName("jwks_uri")]
    public string? JwksUri { get; init; }
}

/// <summary>
/// Protected Resource Metadata (RFC 9728), as this proxy serves it.
/// </summary>
/// <remarks>
/// The document an MCP client reads after a 401 to learn which authorization
/// server to get a token from and what scopes to ask for.
/// </remarks>
internal sealed record ProtectedResourceDocument
{
    [JsonPropertyName("resource")]
    public required string Resource { get; init; }

    [JsonPropertyName("authorization_servers")]
    public required IReadOnlyList<string> AuthorizationServers { get; init; }

    [JsonPropertyName("scopes_supported")]
    public IReadOnlyList<string>? ScopesSupported { get; init; }

    [JsonPropertyName("bearer_methods_supported")]
    public required IReadOnlyList<string> BearerMethodsSupported { get; init; }

    [JsonPropertyName("resource_name")]
    public required string ResourceName { get; init; }
}
