namespace McpGuardrails.Core.Audit;

/// <summary>
/// Destination for audit records.
/// </summary>
/// <remarks>
/// An interface rather than the JSONL sink itself so the call pipeline can be
/// tested against an in-memory sink, including one that has failed. Spans and
/// metrics are not a second sink: they go through ToolCallTelemetry, beside it.
/// </remarks>
public interface IAuditSink : IAsyncDisposable
{
    /// <summary>
    /// True once records can no longer be written.
    /// </summary>
    /// <remarks>
    /// Part of the contract rather than a JsonlAuditSink detail because the
    /// pipeline refuses every call while it is true: a call forwarded with the log
    /// broken would leave no evidence at all.
    /// </remarks>
    bool IsFaulted { get; }

    /// <summary>
    /// Records one audited event.
    /// </summary>
    /// <remarks>
    /// Async because a full buffer applies backpressure rather than discarding
    /// the record. See JsonlAuditSink for why losing audit lines is treated as
    /// worse than briefly slowing a tool call.
    /// </remarks>
    ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken = default);
}
