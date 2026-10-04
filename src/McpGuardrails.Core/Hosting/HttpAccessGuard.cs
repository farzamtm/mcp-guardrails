using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using McpGuardrails.Core.Access;

namespace McpGuardrails.Core.Hosting;

/// <summary>What the HTTP listener should do with a request.</summary>
public enum HttpAccessVerdict
{
    /// <summary>Hand it to the MCP endpoint.</summary>
    Allowed,

    /// <summary>401: a token is required and was missing or wrong.</summary>
    Unauthorized,

    /// <summary>403: a browser page from somewhere other than this machine.</summary>
    ForbiddenOrigin,

    /// <summary>403: a valid access token that does not grant the required scopes.</summary>
    InsufficientScope,

    /// <summary>503: the authorization server's keys are too old to trust, so nothing can be checked.</summary>
    Unavailable,
}

/// <summary>A verdict, with who the caller is and what to tell a refused one.</summary>
/// <param name="Verdict">What to do with the request.</param>
/// <param name="Caller">The validated caller, when the request carried an access token.</param>
/// <param name="Challenge">The <c>WWW-Authenticate</c> value for a 401 or 403, if any.</param>
public sealed record HttpAccessResult(
    HttpAccessVerdict Verdict,
    CallerIdentity? Caller = null,
    string? Challenge = null);

/// <summary>
/// Decides, from two headers, whether an HTTP request may reach the MCP endpoint.
/// </summary>
/// <remarks>
/// Plain strings in, verdict out, so the decision is unit-tested in Core without
/// a web server; the CLI only translates the verdict into a status code.
///
/// Two independent checks:
/// <list type="bullet">
/// <item>The <c>Origin</c> check is what the MCP specification requires of every
/// Streamable HTTP server: a web page can make the browser POST to
/// <c>127.0.0.1</c> (directly, or by DNS rebinding a name it controls), and a
/// loopback bind is no protection against a browser that is already on the
/// machine. Browsers attach <c>Origin</c> to every POST, so a request whose
/// origin is not loopback came from someone else's page. Non-browser clients send
/// no <c>Origin</c> and are unaffected.</item>
/// <item>The bearer token, when configured, is compared in constant time over
/// SHA-256 digests, so neither the content nor the length of the token leaks
/// through response timing.</item>
/// </list>
/// </remarks>
public sealed class HttpAccessGuard
{
    private readonly byte[]? _tokenDigest;

    /// <param name="bearerToken">The token clients must present, or null for none.</param>
    public HttpAccessGuard(string? bearerToken)
    {
        _tokenDigest = bearerToken is null ? null : Digest(bearerToken);
    }

    /// <summary>Judges one request.</summary>
    /// <param name="authorization">The <c>Authorization</c> header, if any.</param>
    /// <param name="origin">The <c>Origin</c> header, if any.</param>
    public HttpAccessVerdict Check(string? authorization, string? origin)
    {
        if (origin is not null && !IsLoopbackOrigin(origin))
        {
            return HttpAccessVerdict.ForbiddenOrigin;
        }

        if (_tokenDigest is null)
        {
            return HttpAccessVerdict.Allowed;
        }

        if (!TryReadBearer(authorization, out var token))
        {
            return HttpAccessVerdict.Unauthorized;
        }

        var presented = Digest(token);

        return CryptographicOperations.FixedTimeEquals(presented, _tokenDigest)
            ? HttpAccessVerdict.Allowed
            : HttpAccessVerdict.Unauthorized;
    }

    /// <summary>Reads the token out of an <c>Authorization: Bearer</c> header.</summary>
    /// <remarks>
    /// The scheme name is case-insensitive (RFC 9110 section 11.1); the token is not.
    /// </remarks>
    internal static bool TryReadBearer(string? authorization, [NotNullWhen(true)] out string? token)
    {
        const string scheme = "Bearer ";

        if (authorization is null ||
            !authorization.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
        {
            token = null;
            return false;
        }

        token = authorization[scheme.Length..].Trim();
        return true;
    }

    /// <remarks>
    /// <c>Origin: null</c> (sandboxed frames, <c>file://</c> pages) fails to parse
    /// and is refused: it is a browser telling us it will not say where it is.
    /// </remarks>
    internal static bool IsLoopbackOrigin(string origin)
    {
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri))
        {
            return false;
        }

        // DnsSafeHost drops the brackets around an IPv6 literal, so "[::1]"
        // arrives as "::1", which IPAddress can parse.
        var host = uri.DnsSafeHost;

        return string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) ||
               (IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address));
    }

    private static byte[] Digest(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));
}
