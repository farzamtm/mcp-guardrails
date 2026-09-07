using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using McpGuardrails.Core.Serialization;

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
/// </remarks>
public sealed class JsonlAuditSink : IAuditSink
{
    private readonly Channel<AuditRecord> _channel;
    private readonly StreamWriter _writer;
    private readonly Task _drainLoop;

    /// <summary>
    /// Opens (or creates) the log file and starts the background writer.
    /// </summary>
    /// <param name="path">File to append to. Parent directories are created.</param>
    /// <param name="capacity">Records buffered before producers start waiting.</param>
    public JsonlAuditSink(string path, int capacity = 10_000)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);

        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        _channel = Channel.CreateBounded<AuditRecord>(
            new BoundedChannelOptions(capacity)
            {
                FullMode = BoundedChannelFullMode.Wait,
                // Telling the channel there is exactly one consumer lets it use a
                // cheaper internal implementation.
                SingleReader = true,
                SingleWriter = false,
            });

        // append: true - never truncate an existing audit log.
        _writer = new StreamWriter(
            new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
        {
            // We flush deliberately at the end of each drained batch instead.
            AutoFlush = false,
        };

        _drainLoop = Task.Run(DrainAsync);
    }

    /// <inheritdoc />
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

    /// <summary>Stops accepting records, drains what is queued, then closes the file.</summary>
    public async ValueTask DisposeAsync()
    {
        // Complete() makes WaitToReadAsync return false once the queue empties,
        // which ends the drain loop cleanly rather than abandoning buffered records.
        _channel.Writer.TryComplete();

        try
        {
            await _drainLoop.ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Shutdown must not throw over a logging failure; the file is closed below.
        }

        await _writer.DisposeAsync().ConfigureAwait(false);
    }
}
