namespace McpGuardrails.Core.Upstream;

/// <summary>
/// How to log in to a remote server with OAuth: the servers file's
/// <c>x-guardrails.oauth</c> block, validated.
/// </summary>
/// <param name="Scopes">
/// Scopes to request. Empty means whatever the server's protected resource
/// metadata suggests, which is what most servers want.
/// </param>
/// <param name="ClientId">
/// A client registered in advance. Null means dynamic client registration
/// (RFC 7591), which the MCP specification has servers support.
/// </param>
/// <param name="RedirectPort">
/// The loopback port for the login redirect. Null means any free port, which
/// works with dynamic registration because each login registers afresh.
/// </param>
public sealed record UpstreamOAuthSettings(
    IReadOnlyList<string> Scopes,
    string? ClientId = null,
    int? RedirectPort = null);
