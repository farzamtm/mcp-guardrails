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
    int? RedirectPort = null)
{
    /// <summary>Validates a server's <c>x-guardrails.oauth</c> block, reporting each problem to <paramref name="error"/>.</summary>
    /// <param name="document">The block as written.</param>
    /// <param name="headers">The server's static headers, to refuse a second credential.</param>
    /// <param name="error">Collects problems; the caller prefixes the server's name.</param>
    /// <remarks>
    /// OAuth and a static Authorization header together are refused: two
    /// credentials for one server is a question about which one is used, and
    /// the answer would be an implementation detail of the SDK.
    /// </remarks>
    internal static UpstreamOAuthSettings Read(
        UpstreamOAuthDocument document, IReadOnlyDictionary<string, string> headers, Action<string> error)
    {
        if (headers.ContainsKey("Authorization"))
        {
            error("sets both an 'Authorization' header and 'x-guardrails.oauth'. Use one: OAuth logs in " +
                  "with 'auth login', a static header sends the same credential every time.");
        }

        var scopes = document.Scopes ?? [];
        foreach (var scope in scopes)
        {
            // RFC 6749 section 3.3's scope-token characters.
            if (string.IsNullOrEmpty(scope) || scope.Any(c => c is < '!' or > '~' or '"' or '\\'))
            {
                error("has an 'x-guardrails.oauth.scopes' entry that is not a single scope name.");
            }
        }

        if (document.ClientId is not null && string.IsNullOrWhiteSpace(document.ClientId))
        {
            error("has an empty 'x-guardrails.oauth.client_id'. Omit it to register dynamically.");
        }

        if (document.RedirectPort is < 1 or > 65535)
        {
            error($"has an 'x-guardrails.oauth.redirect_port' of {document.RedirectPort}; use 1 to 65535.");
        }

        return new UpstreamOAuthSettings(scopes, document.ClientId, document.RedirectPort);
    }
}
