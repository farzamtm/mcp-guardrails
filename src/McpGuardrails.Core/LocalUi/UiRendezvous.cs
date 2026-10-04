using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using McpGuardrails.Core.Serialization;

namespace McpGuardrails.Core.LocalUi;

/// <summary>Where a running local UI listens, and the key the proxy signs approval requests with.</summary>
/// <param name="Url">The UI's loopback base address, e.g. <c>http://127.0.0.1:53817/</c>.</param>
/// <param name="Secret">The per-run HMAC key for the UI's approvals endpoint.</param>
public sealed record UiEndpoint(Uri Url, byte[] Secret)
{
    /// <summary>The path the proxy posts approval questions to.</summary>
    public const string ApprovalsPath = "/api/approvals";

    /// <summary>The absolute address of the approvals API.</summary>
    public Uri ApprovalsUrl => new(Url, ApprovalsPath);
}

/// <summary>
/// The file through which a proxy finds the local UI (<c>~/.mcp-guardrails/ui.json</c>).
/// </summary>
/// <remarks>
/// <para>The UI and the proxy are separate processes, started by different
/// things - the user starts the UI, the MCP client starts the proxy - and either
/// can start first. So the UI writes where it listens and a fresh secret into a
/// file only its owner can read, and the proxy reads that file afresh every time
/// a <c>mode: local_ui</c> rule needs an answer, rather than once at startup: the
/// UI can start, stop or restart while proxies keep running. No file, or one that
/// does not parse, means no UI, and the call is refused.</para>
///
/// <para>The secret is what stops a web page from answering approvals on the
/// user's behalf: the approvals API accepts only requests signed with it, a
/// browser script has no way to learn it, and the file is readable only by
/// whoever the proxy runs as. Anyone who can already read the file can also edit
/// the policy, so it protects against a different attacker than file
/// permissions do.</para>
/// </remarks>
public static class UiRendezvous
{
    /// <summary>The environment variable that overrides the file's location.</summary>
    public const string FileVariable = "GUARDRAILS_UI_FILE";

    /// <summary>The file's name in the configuration directory.</summary>
    public const string FileName = "ui.json";

    /// <summary>The file's contents for a UI listening at <paramref name="endpoint"/>.</summary>
    public static string Serialize(UiEndpoint endpoint, int processId, DateTimeOffset startedAt)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        return JsonSerializer.Serialize(
            new UiRendezvousDocument
            {
                Url = endpoint.Url.AbsoluteUri,
                Secret = Convert.ToBase64String(endpoint.Secret),
                ProcessId = processId,
                StartedAt = startedAt,
            },
            GuardrailsJsonContext.Default.UiRendezvousDocument);
    }

    /// <summary>The endpoint the file names, or null if it names none a proxy should trust.</summary>
    /// <remarks>
    /// Null rather than an exception for every kind of bad file, because there is
    /// only one thing the caller can do about any of them: refuse the call. A URL
    /// that is not plain http to a literal loopback address is refused too - the
    /// signed question carries the call's arguments, and a rewritten or stale file
    /// must never be able to send them anywhere but this machine.
    /// </remarks>
    public static UiEndpoint? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        UiRendezvousDocument? document;
        try
        {
            document = JsonSerializer.Deserialize(text, GuardrailsJsonContext.Default.UiRendezvousDocument);
        }
        catch (JsonException)
        {
            return null;
        }

        if (document is not { Version: UiRendezvousDocument.CurrentVersion, Url: { } url, Secret: { } secret }
            || !Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || !IsLoopbackHttp(uri)
            || !TryDecode(secret, out var key))
        {
            return null;
        }

        return new UiEndpoint(uri, key);
    }

    /// <summary>Whether <paramref name="uri"/> is plain http to a literal loopback address.</summary>
    internal static bool IsLoopbackHttp(Uri uri) =>
        uri.Scheme == Uri.UriSchemeHttp
        && string.IsNullOrEmpty(uri.UserInfo)
        && IPAddress.TryParse(uri.IdnHost, out var address)
        && IPAddress.IsLoopback(address);

    private static bool TryDecode(string secret, out byte[] key)
    {
        key = [];

        try
        {
            key = Convert.FromBase64String(secret);
        }
        catch (FormatException)
        {
            return false;
        }

        // 128 bits at least: anything shorter would be guessable by anything
        // that can reach the port, which on a shared machine is every local user.
        return key.Length >= 16;
    }
}

/// <summary>The wire format of the rendezvous file.</summary>
internal sealed record UiRendezvousDocument
{
    public const int CurrentVersion = 1;

    [JsonPropertyName("version")]
    public int Version { get; init; } = CurrentVersion;

    [JsonPropertyName("url")]
    public string? Url { get; init; }

    [JsonPropertyName("secret")]
    public string? Secret { get; init; }

    [JsonPropertyName("pid")]
    public int? ProcessId { get; init; }

    [JsonPropertyName("started_at")]
    public DateTimeOffset? StartedAt { get; init; }
}
