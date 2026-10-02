using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using McpGuardrails.Core.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace McpGuardrails.Core.Audit;

/// <summary>
/// Appends audit records to a newline-delimited JSON file, off the calling thread.
/// </summary>
/// <remarks>
/// This is the one place in the proxy where System.Threading.Channels genuinely
/// earns its keep, so it is worth being precise about why.
///
/// A tool call must not wait for a disk write. But an audit log that silently
/// drops lines under load is worthless for a security tool - "no record exists"
/// and "nothing happened" would become indistinguishable. So:
///
///   - producers (tool calls) hand records to a BOUNDED channel and move on
///   - a single background consumer owns the file and does all the I/O
///   - when the buffer fills, producers WAIT rather than discard
///
/// That last choice is the interesting one. FullMode.Wait means a disk that
/// cannot keep up will eventually slow the agent down. The alternative,
/// DropWrite, keeps the agent fast by losing evidence. For an auditing tool the
/// first failure mode is the acceptable one, and 10,000 buffered records means
/// it is essentially unreachable in practice.
///
/// A single consumer also removes all locking: only one thread ever touches the
/// StreamWriter, so there is no synchronisation to get wrong.
///
/// The same reasoning decides what happens when the disk itself fails. Carrying
/// on without a log would be the DropWrite trade made permanent, so the sink
/// fails closed instead: the error is logged, IsFaulted turns true, and every
/// WriteAsync from then on throws rather than queueing evidence that will never
/// be written. See DrainAsync.
/// </remarks>
public sealed class JsonlAuditSink : IAuditSink
{
    private readonly Channel<AuditRecord> _channel;
    private readonly StreamWriter _writer;
    private readonly Task _drainLoop;
    private readonly ILogger _logger;
    private readonly string _name;

    // Written once by the drain loop, read by any producer thread.
    private volatile Exception? _fault;

    /// <summary>
    /// Opens (or creates) the log file and starts the background writer.
    /// </summary>
    /// <param name="path">File to append to. Parent directories are created.</param>
    /// <param name="capacity">Records buffered before producers start waiting.</param>
    /// <param name="logger">Where a write failure is reported. Must reach stderr, not stdout.</param>
    public JsonlAuditSink(string path, int capacity = 10_000, ILogger? logger = null)
        : this(OpenForAppend(path, capacity), capacity, logger, path)
    {
    }

    /// <summary>
    /// Test seam: writes to an arbitrary stream, so a test can inject one that
    /// fails the way a full or vanished disk does.
    /// </summary>
    internal JsonlAuditSink(Stream stream, int capacity, ILogger? logger, string name)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);

        _logger = logger ?? NullLogger.Instance;
        _name = name;

        _channel = Channel.CreateBounded<AuditRecord>(
            new BoundedChannelOptions(capacity)
            {
                FullMode = BoundedChannelFullMode.Wait,
                // Telling the channel there is exactly one consumer lets it use a
                // cheaper internal implementation.
                SingleReader = true,
                SingleWriter = false,
            });

        _writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
        {
            // We flush deliberately at the end of each drained batch instead.
            AutoFlush = false,
        };

        _drainLoop = Task.Run(DrainAsync);
    }

    // Validates before touching the file system, so a bad capacity fails as an
    // argument error rather than as a sharing violation against an open log.
    private static FileStream OpenForAppend(string path, int capacity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);

        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // FileMode.Append - never truncate an existing audit log.
        return new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
    }

    /// <summary>
    /// True once the log could not be written. From then on WriteAsync throws, and
    /// callers that must not act unaudited should refuse before acting.
    /// </summary>
    public bool IsFaulted => _fault is not null;

    /// <inheritdoc />
    /// <exception cref="ChannelClosedException">
    /// The log could not be written; the inner exception says why.
    /// </exception>
    public ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        return _channel.Writer.WriteAsync(record, cancellationToken);
    }

    /// <summary>
    /// The single consumer: drains the channel in batches and flushes once per batch.
    /// </summary>
    /// <remarks>
    /// The nested loop is the point. WaitToReadAsync parks until something arrives;
    /// the inner TryRead loop then takes everything currently queued without
    /// awaiting. So a burst of 500 calls costs one flush, not 500, while a single
    /// quiet call still reaches disk immediately.
    /// </remarks>
    private async Task DrainAsync()
    {
        var reader = _channel.Reader;

        try
        {
            while (await reader.WaitToReadAsync().ConfigureAwait(false))
            {
                while (reader.TryRead(out var record))
                {
                    // Serializing against the source-generated handle rather than by
                    // Type is what keeps this Native AOT safe.
                    var json = JsonSerializer.Serialize(
                        record, GuardrailsJsonContext.Default.AuditRecord);

                    await _writer.WriteLineAsync(json).ConfigureAwait(false);
                }

                await _writer.FlushAsync().ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            // Fail closed. This loop is the only consumer, so if it simply ended
            // the bounded channel would fill and every producer - every tool call -
            // would wait forever on a record nobody will ever read. Completing the
            // channel WITH the error instead wakes those waiters and makes every
            // later WriteAsync throw at once, so the failure reaches the call path
            // where it can be refused rather than hung.
            //
            // No retry: what breaks a local append - a full disk, a deleted or
            // revoked file - does not heal in milliseconds, and retrying in a loop
            // would only reintroduce the backpressure stall this is escaping. Nor
            // is a single unserialisable record skipped: skipping would be exactly
            // the silent gap in the evidence this class exists to rule out.
            //
            // _fault is published before the channel is completed so that anyone
            // who sees a closed channel also sees IsFaulted.
            _fault = ex;
            _channel.Writer.TryComplete(ex);

            // Records accepted but never written cannot be saved, but they can be
            // counted, so the gap in the log is at least visible and sized.
            var lost = 0;
            while (reader.TryRead(out _))
            {
                lost++;
            }

            _logger.LogCritical(
                ex,
                "Audit log '{AuditLog}' can no longer be written. {Lost} queued record(s) were lost, " +
                "plus any not yet flushed. Further audited calls will be refused.",
                _name,
                lost);
        }
    }

    /// <summary>Stops accepting records, drains what is queued, then closes the file.</summary>
    public async ValueTask DisposeAsync()
    {
        // Complete() makes WaitToReadAsync return false once the queue empties,
        // which ends the drain loop cleanly rather than abandoning buffered records.
        _channel.Writer.TryComplete();

        // The drain loop handles its own failures, so this cannot throw.
        await _drainLoop.ConfigureAwait(false);

        try
        {
            await _writer.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Closing flushes, and after a write failure the flush fails the same
            // way. Shutdown must not throw over that - but it must not hide it either.
            _logger.LogError(ex, "Audit log '{AuditLog}' could not be closed cleanly.", _name);
        }
    }
}
