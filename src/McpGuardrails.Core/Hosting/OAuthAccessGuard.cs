using System.Text.Json;
using McpGuardrails.Core.Access;
using McpGuardrails.Core.Serialization;

namespace McpGuardrails.Core.Hosting;

/// <summary>
/// Decides whether an HTTP request may reach the MCP endpoint when
/// <c>access.oauth</c> is configured, and what to tell it when it may not.
/// </summary>
/// <remarks>
/// The protected-resource half of the MCP authorization specification. A
/// request with no token, or a bad one, gets a 401 whose
/// <c>WWW-Authenticate</c> header points at the Protected Resource Metadata
/// (RFC 9728), and that document names the authorization server - which is all
/// a compliant client needs to go and get a token by itself. The Origin check
/// from <see cref="HttpAccessGuard"/> still runs first: a token does not make a
/// foreign web page's request safe to serve.
///
/// Headers and URLs in, verdict out, like <see cref="HttpAccessGuard"/>, so the
/// decision is unit-tested without a web server. That includes which paths are
/// the metadata document: the 401 points clients at a URL, and the rule that
/// answers that URL lives beside the rule that builds it.
/// </remarks>
public sealed class OAuthAccessGuard : IHttpAccessGuard
{
    /// <summary>Where the Protected Resource Metadata is served (RFC 9728 section 3).</summary>
    public const string MetadataPath = "/.well-known/oauth-protected-resource";

    private readonly OAuthSettings _settings;
    private readonly AccessTokenValidator _validator;

    /// <param name="settings">The validated <c>access.oauth</c> block.</param>
    /// <param name="validator">Checks the tokens.</param>
    public OAuthAccessGuard(OAuthSettings settings, AccessTokenValidator validator)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(validator);

        _settings = settings;
        _validator = validator;
    }

    /// <inheritdoc />
    public ValueTask<HttpAccessResult> CheckAsync(HttpAccessRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var resource = Resource(request.Scheme, request.Host, request.Endpoint);

        // Public by definition: it is how a client without a token finds out
        // where to get one.
        if (IsMetadataRequest(request.Method, request.Path, resource))
        {
            return ValueTask.FromResult(
                new HttpAccessResult(HttpAccessVerdict.Metadata, Document: MetadataDocument(resource)));
        }

        return CheckAsync(request.Authorization, request.Origin, resource, cancellationToken);
    }

    /// <summary>Judges one request to the MCP endpoint.</summary>
    /// <param name="authorization">The <c>Authorization</c> header, if any.</param>
    /// <param name="origin">The <c>Origin</c> header, if any.</param>
    /// <param name="resource">This proxy's resource URL, from <see cref="Resource"/>.</param>
    /// <param name="cancellationToken">The request's cancellation.</param>
    public async ValueTask<HttpAccessResult> CheckAsync(
        string? authorization,
        string? origin,
        Uri resource,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);

        if (origin is not null && !HttpAccessGuard.IsLoopbackOrigin(origin))
        {
            return new HttpAccessResult(HttpAccessVerdict.ForbiddenOrigin);
        }

        var metadata = MetadataUrl(resource);

        // No error code for a request that sent no token at all: RFC 6750
        // section 3.1 reserves them for a token that was sent and failed.
        if (!HttpAccessGuard.TryReadBearer(authorization, out var token))
        {
            return new HttpAccessResult(HttpAccessVerdict.Unauthorized, Challenge: Challenge(metadata));
        }

        var check = await _validator.ValidateAsync(token, cancellationToken);

        return check.Status switch
        {
            TokenStatus.Valid => new HttpAccessResult(HttpAccessVerdict.Allowed, check.Caller),
            TokenStatus.InsufficientScope => new HttpAccessResult(
                HttpAccessVerdict.InsufficientScope,
                Challenge: Challenge(metadata, "insufficient_scope", check.Problem)),
            // No challenge: the client did nothing wrong, and a 401 would send it
            // off to fetch a new token that would fail in exactly the same way.
            TokenStatus.Unavailable => new HttpAccessResult(HttpAccessVerdict.Unavailable),
            _ => new HttpAccessResult(
                HttpAccessVerdict.Unauthorized,
                Challenge: Challenge(metadata, "invalid_token", check.Problem)),
        };
    }

    /// <summary>
    /// This proxy's resource URL: the configured <c>resource</c>, or the URL of
    /// the endpoint as the request reached it.
    /// </summary>
    /// <remarks>
    /// Built from the request when not configured, so a proxy on a loopback port
    /// works with no extra setting. That URL reflects the request's
    /// <c>Host</c> header back into the challenge and the metadata document. It
    /// goes only to the client that sent it, and the audience check uses the
    /// configured <c>audience</c>, so it decides nothing - but behind a
    /// TLS-terminating reverse proxy the request's own scheme and host are the
    /// wrong ones, which is what <c>resource</c> is for. No host, or one that
    /// does not make a URL, falls back to loopback rather than failing the
    /// request.
    /// </remarks>
    public Uri Resource(string scheme, string? host, string endpointPath) =>
        _settings.ResourceUri
        ?? (host is not null && Uri.TryCreate($"{scheme}://{host}{endpointPath}", UriKind.Absolute, out var uri)
            ? uri
            : new Uri($"http://localhost{endpointPath}"));

    /// <summary>Whether a request asks for the metadata of <paramref name="resource"/>.</summary>
    /// <remarks>
    /// Both RFC 9728 locations: the path-suffixed one <see cref="MetadataUrl"/>
    /// builds, which the MCP specification has clients try first, and the bare
    /// well-known path for clients that do not. GET or HEAD only.
    /// </remarks>
    public static bool IsMetadataRequest(string method, string path, Uri resource)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return (string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase)) &&
               (path == MetadataPath || path == MetadataPath + resource.AbsolutePath.TrimEnd('/'));
    }

    /// <summary>Where the metadata for <paramref name="resource"/> is served.</summary>
    /// <remarks>
    /// The RFC 9728 form: the well-known prefix inserted between the host and the
    /// resource's path, so <c>https://host/mcp</c> has its metadata at
    /// <c>https://host/.well-known/oauth-protected-resource/mcp</c>.
    /// </remarks>
    public static Uri MetadataUrl(Uri resource)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return new Uri(
            $"{resource.GetLeftPart(UriPartial.Authority)}{MetadataPath}{resource.AbsolutePath.TrimEnd('/')}");
    }

    /// <summary>The Protected Resource Metadata document for <paramref name="resource"/>.</summary>
    public string MetadataDocument(Uri resource)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return JsonSerializer.Serialize(
            new ProtectedResourceDocument
            {
                Resource = resource.AbsoluteUri,
                AuthorizationServers = [_settings.Issuer!],
                ScopesSupported = _settings.EffectiveRequiredScopes.Count > 0 ? _settings.EffectiveRequiredScopes : null,
                BearerMethodsSupported = ["header"],
                ResourceName = "mcp-guardrails",
            },
            AccessJsonContext.Default.ProtectedResourceDocument);
    }

    /// <remarks>
    /// The scope parameter tells a client what to ask for on its next attempt
    /// (the MCP specification's scope selection). Every value in the header is a
    /// configured scope, a fixed phrase or the metadata URL. That URL carries
    /// the request's own <c>Host</c> when <c>resource</c> is not configured (see
    /// <see cref="Resource"/>), normalized by <see cref="Uri"/>; nothing else a
    /// client sent is reflected into the header.
    /// </remarks>
    private string Challenge(Uri metadata, string? error = null, string? description = null)
    {
        var parts = new List<string>(4);

        if (error is not null)
        {
            parts.Add($"error=\"{error}\"");
            parts.Add($"error_description=\"{description}\"");
        }

        if (_settings.EffectiveRequiredScopes.Count > 0)
        {
            parts.Add($"scope=\"{string.Join(' ', _settings.EffectiveRequiredScopes)}\"");
        }

        parts.Add($"resource_metadata=\"{metadata.AbsoluteUri}\"");

        return "Bearer " + string.Join(", ", parts);
    }
}
