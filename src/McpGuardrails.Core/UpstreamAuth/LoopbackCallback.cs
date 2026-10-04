using ModelContextProtocol.Authentication;

namespace McpGuardrails.Core.UpstreamAuth;

/// <summary>
/// The browser's return from the authorization server to <c>auth login</c>'s
/// loopback listener: one HTTP request line, read into a code or an error.
/// </summary>
/// <remarks>
/// A hand-read request line rather than a web server: the listener accepts
/// exactly one request, on 127.0.0.1, for the few minutes a login takes. The
/// <c>state</c> is checked by the SDK against the one it generated, which is
/// what stops another page from completing someone else's login here.
/// </remarks>
public static class LoopbackCallback
{
    /// <summary>The path the redirect URI points at.</summary>
    public const string Path = "/callback";

    /// <summary>The page shown in the browser afterwards.</summary>
    public static string Page(bool succeeded) =>
        "<!doctype html><meta charset=\"utf-8\"><title>mcp-guardrails</title><p>" +
        (succeeded
            ? "Logged in. You can close this window and return to the terminal."
            : "The login did not complete. Return to the terminal for details.") +
        "</p>";

    /// <summary>Reads the authorization response out of an HTTP request line.</summary>
    /// <param name="requestLine">E.g. <c>GET /callback?code=...&amp;state=... HTTP/1.1</c>.</param>
    /// <exception cref="InvalidOperationException">
    /// Not a callback, or the authorization server sent an error. The message is
    /// meant for the person at the terminal.
    /// </exception>
    public static AuthorizationResult Parse(string? requestLine)
    {
        var parts = requestLine?.Split(' ');

        if (parts is not [var method, var target, _] || method != "GET" ||
            !Uri.TryCreate(new Uri("http://127.0.0.1"), target, out var uri) ||
            uri.AbsolutePath != Path)
        {
            throw new InvalidOperationException("The browser came back with something that is not a login callback.");
        }

        var query = Query(uri.Query);

        if (query.TryGetValue("error", out var error))
        {
            // The error code is from a fixed vocabulary (RFC 6749 section 4.1.2.1),
            // but quoted with care anyway: it came through someone's browser.
            throw new InvalidOperationException(
                $"The authorization server refused the login ({Printable(error)}" +
                (query.TryGetValue("error_description", out var description) ? $": {Printable(description)}" : string.Empty) +
                ").");
        }

        if (!query.TryGetValue("code", out var code) || code.Length == 0)
        {
            throw new InvalidOperationException("The login callback carried no authorization code.");
        }

        return new AuthorizationResult
        {
            Code = code,
            State = query.GetValueOrDefault("state"),
            Iss = query.GetValueOrDefault("iss"),
        };
    }

    private static Dictionary<string, string> Query(string query)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = pair.IndexOf('=');
            var key = Uri.UnescapeDataString((separator < 0 ? pair : pair[..separator]).Replace('+', ' '));
            var value = separator < 0 ? string.Empty : Uri.UnescapeDataString(pair[(separator + 1)..].Replace('+', ' '));

            // The first occurrence wins; a repeated parameter is not a second chance.
            values.TryAdd(key, value);
        }

        return values;
    }

    private static string Printable(string text)
    {
        var clean = new string([.. text.Where(c => !char.IsControl(c))]);
        return clean.Length > 200 ? clean[..200] : clean;
    }
}
