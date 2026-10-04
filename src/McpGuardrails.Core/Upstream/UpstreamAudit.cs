using McpGuardrails.Core.Audit;

namespace McpGuardrails.Core.Upstream;

/// <summary>The audit log's record of which servers a session was connected to.</summary>
/// <remarks>
/// One line per server at startup. Without it the log says what each tool call
/// did but not which program answered it - and after someone edits the servers
/// file, "fs" in yesterday's log may not be the "fs" running today.
/// </remarks>
public static class UpstreamAudit
{
    /// <summary>The audit log's <c>event</c> for a server connected at startup.</summary>
    public const string ConnectedEvent = "upstream_connected";

    /// <summary>The transport as the audit log spells it.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not a defined transport.</exception>
    public static string ToWireName(this UpstreamTransport transport) => transport switch
    {
        UpstreamTransport.Stdio => "stdio",
        UpstreamTransport.Http => "http",
        UpstreamTransport.Sse => "sse",
        _ => throw new ArgumentOutOfRangeException(nameof(transport), transport, "No wire name for this transport."),
    };

    /// <summary>The <c>upstream_connected</c> line for one connection.</summary>
    public static AuditRecord Connected(UpstreamConnection connection, DateTimeOffset timestamp)
    {
        ArgumentNullException.ThrowIfNull(connection);

        var config = connection.Config;

        return new AuditRecord
        {
            Timestamp = timestamp,
            Event = ConnectedEvent,
            Server = connection.Name,
            Transport = (config?.Transport ?? UpstreamTransport.Stdio).ToWireName(),
            ToolCount = connection.Tools.Count,
            Identity = config?.DisplayTemplate,
            DurationMs = 0,
            IsError = false,
        };
    }
}
