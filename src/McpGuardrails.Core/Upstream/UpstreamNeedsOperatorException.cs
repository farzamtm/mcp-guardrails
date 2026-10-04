namespace McpGuardrails.Core.Upstream;

/// <summary>
/// A server the proxy cannot use until a person does something - log in, renew
/// a credential - that no retry can do for them.
/// </summary>
/// <remarks>
/// The registry and the call pipeline treat it the same way whatever the cause:
/// the server's tools are absent rather than the proxy refusing to start, and a
/// call that hits it is a tool error the model reads and passes on. A base type
/// in this namespace rather than OAuth's own, so neither of them has to know
/// which feature raised it.
/// </remarks>
/// <param name="server">The server's name.</param>
/// <param name="message">What happened and what to run, for the operator and the model.</param>
public class UpstreamNeedsOperatorException(string server, string message) : Exception(message)
{
    /// <summary>The server's name.</summary>
    public string Server { get; } = server;

    /// <summary>The first such failure in <paramref name="error"/>, if there is one.</summary>
    /// <remarks>
    /// Searched through inner exceptions because the SDK wraps what a callback
    /// throws on its way out of a request.
    /// </remarks>
    public static UpstreamNeedsOperatorException? Find(Exception? error)
    {
        for (var current = error; current is not null; current = current.InnerException)
        {
            if (current is UpstreamNeedsOperatorException found)
            {
                return found;
            }

            if (current is AggregateException aggregate)
            {
                return aggregate.InnerExceptions.Select(Find).FirstOrDefault(inner => inner is not null);
            }
        }

        return null;
    }
}
