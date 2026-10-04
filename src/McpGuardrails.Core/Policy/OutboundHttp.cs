namespace McpGuardrails.Core.Policy;

/// <summary>
/// The transport for every request the proxy sends to a URL from the policy
/// file: approval webhooks and the authorization server's signing keys.
/// </summary>
/// <remarks>
/// One factory beside <see cref="OutboundUrl"/>, for the same reason that class
/// exists: a hardening added to one copy of a handler and forgotten in another
/// is a gap nobody sees.
/// </remarks>
public static class OutboundHttp
{
    /// <summary>A handler with redirects off and connections recycled.</summary>
    /// <remarks>
    /// Redirects off: a 3xx asks for the request to go somewhere the policy did
    /// not name - possibly over plain http - and following it would bypass every
    /// check made on the URL. Not following it makes it a non-2xx answer, which
    /// every caller treats as a failure.
    ///
    /// Connections recycled: the process can live as long as the client session,
    /// and an endpoint behind a load balancer moves, so DNS is re-resolved now
    /// and then.
    /// </remarks>
    public static SocketsHttpHandler CreateHandler() => new()
    {
        AllowAutoRedirect = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    };
}
