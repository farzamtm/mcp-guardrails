namespace McpGuardrails.Core.Policy;

/// <summary>
/// Validation for a URL in the policy file that the proxy will send requests to.
/// </summary>
/// <remarks>
/// One implementation for every outbound endpoint, because two copies had
/// already drifted: one accepted credentials in the URL and the other did not.
/// The rules are the ones any endpoint carrying a secret or a decision needs, and
/// a new endpoint should get all of them by calling this rather than by
/// remembering them.
/// </remarks>
internal static class OutboundUrl
{
    /// <summary>
    /// Parses <paramref name="value"/> and checks it is safe to send to, throwing a
    /// <see cref="PolicyException"/> that names <paramref name="setting"/> if not.
    /// </summary>
    /// <param name="value">The URL as written in the policy file.</param>
    /// <param name="setting">The dotted key, e.g. <c>approvers.webhook.url</c>, quoted in errors.</param>
    /// <param name="reason">
    /// Why https matters for this endpoint, as a sentence without a full stop.
    /// </param>
    /// <param name="credentialHint">
    /// Where this endpoint's credential belongs instead, as a clause without a full stop.
    /// </param>
    /// <param name="allowLoopbackHttp">Whether plain http to a loopback address is accepted.</param>
    /// <param name="optInSetting">
    /// The key that sets <paramref name="allowLoopbackHttp"/>, named in errors so the
    /// operator knows how to get it; <see langword="null"/> when loopback http needs
    /// no opt-in.
    /// </param>
    internal static Uri Validate(
        string value,
        string setting,
        string reason,
        string credentialHint,
        bool allowLoopbackHttp,
        string? optInSetting = null)
    {
        // The value is deliberately not echoed in any message: a URL that failed
        // to parse may still carry the credentials this check exists to keep out
        // of logs.
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            throw new PolicyException($"'{setting}' is not an absolute URL.");
        }

        // A credential in the URL ends up wherever the URL is printed - startup
        // logs, error messages, an issue someone pastes the policy into.
        if (uri.UserInfo.Length > 0)
        {
            throw new PolicyException(
                $"'{setting}' contains credentials. Keep secrets out of the policy file; " +
                $"{credentialHint}.");
        }

        if (uri.Scheme == Uri.UriSchemeHttps)
        {
            return uri;
        }

        if (uri.Scheme != Uri.UriSchemeHttp)
        {
            throw new PolicyException($"'{setting}' uses '{uri.Scheme}'. Use https.");
        }

        if (!allowLoopbackHttp)
        {
            var escape = optInSetting is null
                ? string.Empty
                : $" - or, for a receiver on this machine only, set '{optInSetting}: true'";

            throw new PolicyException($"'{setting}' uses plain http. {reason}, so use https{escape}.");
        }

        if (!uri.IsLoopback)
        {
            var scope = optInSetting is null
                ? "plain http is accepted only for loopback addresses"
                : $"'{optInSetting}' only permits loopback addresses";

            throw new PolicyException(
                $"'{setting}' uses plain http to '{uri.Host}', but {scope} (localhost, 127.0.0.1, " +
                $"::1). {reason}, so use https for anything else.");
        }

        return uri;
    }
}
