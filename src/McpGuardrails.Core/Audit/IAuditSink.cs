namespace McpGuardrails.Core.Audit;

/// <summary>
/// Destination for audit records.
/// </summary>
/// <remarks>
/// An interface rather than a concrete class because the spec calls for a second
/// implementation (OpenTelemetry) alongside the JSONL file, and because tests
/// want an in-memory one. This is the same swap-the-implementation shape the
/// budget store will use in step 7.
/// </remarks>
public interface IAuditSink : IAsyncDisposable
{
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
