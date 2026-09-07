using System.Text.Json;
using McpGuardrails.Core.Audit;

namespace McpGuardrails.Core.Tests.Audit;

/// <summary>
/// Tests for the channel-backed audit sink.
/// </summary>
/// <remarks>
/// xUnit creates a new instance of the test class per test, so the temp
/// directory below is unique to each one and they cannot interfere. Implementing
/// IDisposable gives us teardown - it runs after each test.
/// </remarks>
public sealed class JsonlAuditSinkTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), $"guardrails-tests-{Guid.NewGuid():N}");

    private string LogPath => Path.Combine(_directory, "audit.jsonl");

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private static AuditRecord Record(string tool) => new()
    {
        Timestamp = DateTimeOffset.UnixEpoch,
        Event = "tool_call",
        Tool = tool,
        DurationMs = 1.5,
        IsError = false,
    };

    private async Task<IReadOnlyList<JsonElement>> ReadLogAsync()
    {
        var lines = await File.ReadAllLinesAsync(LogPath);
        return [.. lines
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .Select(line => JsonDocument.Parse(line).RootElement.Clone())];
    }

    [Fact]
    public async Task WritesOneJsonLinePerRecord()
    {
        await using (var sink = new JsonlAuditSink(LogPath))
        {
            await sink.WriteAsync(Record("fs__read_file"));
            await sink.WriteAsync(Record("fs__write_file"));
        }

        var entries = await ReadLogAsync();

        Assert.Equal(2, entries.Count);
        Assert.Equal("fs__read_file", entries[0].GetProperty("tool").GetString());
        Assert.Equal("fs__write_file", entries[1].GetProperty("tool").GetString());
    }

    [Fact]
    public async Task CreatesParentDirectory()
    {
        var nested = Path.Combine(_directory, "deep", "deeper", "audit.jsonl");

        await using (var sink = new JsonlAuditSink(nested))
        {
            await sink.WriteAsync(Record("fs__read_file"));
        }

        Assert.True(File.Exists(nested));
    }

    /// <summary>
    /// The guarantee that makes the sink trustworthy: shutting down must flush
    /// everything still queued rather than abandoning it.
    /// </summary>
    [Fact]
    public async Task DisposeDrainsBufferedRecords()
    {
        const int count = 500;

        await using (var sink = new JsonlAuditSink(LogPath))
        {
            for (var i = 0; i < count; i++)
            {
                await sink.WriteAsync(Record($"fs__tool_{i}"));
            }
        }

        var entries = await ReadLogAsync();

        Assert.Equal(count, entries.Count);
        // Order must be preserved: a channel is FIFO, and an audit log that
        // reorders events is misleading evidence.
        Assert.Equal("fs__tool_0", entries[0].GetProperty("tool").GetString());
        Assert.Equal($"fs__tool_{count - 1}", entries[^1].GetProperty("tool").GetString());
    }

    [Fact]
    public async Task AppendsToAnExistingLogRatherThanTruncating()
    {
        await using (var first = new JsonlAuditSink(LogPath))
        {
            await first.WriteAsync(Record("fs__first"));
        }

        await using (var second = new JsonlAuditSink(LogPath))
        {
            await second.WriteAsync(Record("fs__second"));
        }

        var entries = await ReadLogAsync();

        Assert.Equal(2, entries.Count);
        Assert.Equal("fs__first", entries[0].GetProperty("tool").GetString());
    }

    [Fact]
    public async Task OmitsNullFieldsToKeepTheLogNarrow()
    {
        await using (var sink = new JsonlAuditSink(LogPath))
        {
            await sink.WriteAsync(Record("fs__read_file"));
        }

        var entry = (await ReadLogAsync())[0];

        // Server, downstream_tool, arguments and error were all null.
        Assert.False(entry.TryGetProperty("server", out _));
        Assert.False(entry.TryGetProperty("error", out _));
        Assert.True(entry.TryGetProperty("tool", out _));
    }

    [Fact]
    public async Task RejectsInvalidConstructorArguments()
    {
        Assert.Throws<ArgumentException>(() => new JsonlAuditSink("  "));

        await using var sink = new JsonlAuditSink(LogPath);
        Assert.Throws<ArgumentOutOfRangeException>(() => new JsonlAuditSink(LogPath, capacity: 0));
        await Assert.ThrowsAsync<ArgumentNullException>(
            async () => await sink.WriteAsync(null!));
    }
}
