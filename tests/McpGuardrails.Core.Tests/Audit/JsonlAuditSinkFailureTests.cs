using System.Threading.Channels;
using McpGuardrails.Core.Audit;
using Microsoft.Extensions.Logging;

namespace McpGuardrails.Core.Tests.Audit;

/// <summary>
/// What the sink does when the disk stops cooperating.
/// </summary>
/// <remarks>
/// Every await here carries a timeout. The bug these tests guard against is a
/// HANG, and a test that hangs on regression is far worse than one that fails.
/// </remarks>
public sealed class JsonlAuditSinkFailureTests
{
    private static readonly TimeSpan _timeout = TimeSpan.FromSeconds(10);

    private static AuditRecord Record(int i) => new()
    {
        Timestamp = DateTimeOffset.UnixEpoch,
        Event = "tool_call",
        Tool = $"fs__tool_{i}",
        DurationMs = 1,
        IsError = false,
    };

    /// <summary>
    /// Regression: the drain loop used to die silently on the first I/O error,
    /// after which the bounded channel filled and every producer - every tool
    /// call - blocked forever.
    /// </summary>
    [Fact]
    public async Task WriteFailure_FailsProducersPromptlyInsteadOfHanging()
    {
        await using var sink = new JsonlAuditSink(new FailingStream(), capacity: 1, logger: null, "test");

        var ex = await Assert.ThrowsAsync<ChannelClosedException>(async () =>
        {
            // Far more than the capacity: without the fix, the third write parks
            // forever and the timeout turns that into a failure.
            for (var i = 0; i < 100; i++)
            {
                await sink.WriteAsync(Record(i)).AsTask().WaitAsync(_timeout);
            }
        });

        Assert.IsType<IOException>(ex.InnerException);
        Assert.True(sink.IsFaulted);
    }

    /// <summary>
    /// Fail closed, but loudly: the operator is told the log broke and how many
    /// accepted records never reached it.
    /// </summary>
    [Fact]
    public async Task WriteFailure_IsLoggedWithTheNumberOfQueuedRecordsLost()
    {
        var stream = new GatedFailingStream();
        var logger = new RecordingLogger();
        var sink = new JsonlAuditSink(stream, capacity: 10, logger, "audit.jsonl");

        // The first record parks the drain loop inside the write...
        await sink.WriteAsync(Record(0));
        await stream.Entered.WaitAsync(_timeout);

        Assert.False(sink.IsFaulted);

        // ...so these three are queued behind it when the write fails.
        for (var i = 1; i <= 3; i++)
        {
            await sink.WriteAsync(Record(i));
        }

        stream.Release.SetResult();

        // Dispose waits for the drain loop, so the failure has been handled once
        // it returns. It must still complete, and must not throw even though
        // closing the writer fails the same way the write did.
        await sink.DisposeAsync().AsTask().WaitAsync(_timeout);

        Assert.True(sink.IsFaulted);

        var critical = Assert.Single(logger.Entries, e => e.Level == LogLevel.Critical);
        Assert.IsType<IOException>(critical.Exception);
        Assert.Contains("'audit.jsonl'", critical.Message);
        Assert.Contains("3 queued record(s) were lost", critical.Message);

        var closing = Assert.Single(logger.Entries, e => e.Level == LogLevel.Error);
        Assert.IsType<IOException>(closing.Exception);
    }
}

/// <summary>Captures log entries so a test can assert the failure was reported.</summary>
internal sealed class RecordingLogger : ILogger
{
    public List<(LogLevel Level, string Message, Exception? Exception)> Entries { get; } = [];

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        lock (Entries)
        {
            Entries.Add((logLevel, formatter(state, exception), exception));
        }
    }
}

/// <summary>
/// Fails its first write only once released, so a test can queue records behind
/// a write that is known to be in progress.
/// </summary>
internal sealed class GatedFailingStream : FailingStreamBase
{
    private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public Task Entered => _entered.Task;

    public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        _entered.TrySetResult();
        await Release.Task;
        throw Fail();
    }
}

/// <summary>A stream that fails every write, the way a full disk does.</summary>
internal sealed class FailingStream : FailingStreamBase;

internal abstract class FailingStreamBase : Stream
{
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => throw Fail();

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.FromException(Fail());

    public override void Write(byte[] buffer, int offset, int count) => throw Fail();

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
        ValueTask.FromException(Fail());

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        Task.FromException(Fail());

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected static IOException Fail() => new("No space left on device");
}
