using McpGuardrails.Core.Budget;
using Microsoft.Data.Sqlite;

namespace McpGuardrails.Core.Tests.Budget;

/// <summary>
/// The daily store against real SQLite files in a throwaway directory. Real
/// files, not mocks: what is under test is precisely the behaviour a mock would
/// fake - persistence across instances and locking across connections.
/// </summary>
public sealed class SqliteBudgetStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "guardrails-budget-tests",
        Guid.NewGuid().ToString("N"));

    private readonly FakeClock _clock = new(new DateTimeOffset(2026, 10, 1, 12, 0, 0, TimeSpan.Zero));

    private string DbPath => Path.Combine(_directory, "budgets.db");

    private SqliteBudgetStore Open(long? maxCalls = null, long? maxCost = null) =>
        new(DbPath, new BudgetLimits { MaxCalls = maxCalls, MaxCost = maxCost }, _clock);

    public void Dispose()
    {
        // Pooling is off in the store, so nothing holds the file once the
        // instances are disposed and the directory can go.
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    // ----------------------------------------------------------- persistence

    [Fact]
    public void Spend_SurvivesReopeningTheFile()
    {
        // The whole reason this store exists: a restart must not reset the day.
        using (var first = Open(maxCalls: 2))
        {
            Assert.True(first.TryCharge(3).Allowed);
            Assert.True(first.TryCharge(4).Allowed);
        }

        using var second = Open(maxCalls: 2);

        Assert.Equal(2, second.Calls);
        Assert.Equal(7, second.Cost);

        var refused = second.TryCharge(0);

        Assert.False(refused.Allowed);
        Assert.Equal(BudgetDimension.Calls, refused.Exceeded);
        Assert.Equal(2, refused.Used);
        Assert.Equal(2, refused.Cap);
    }

    [Fact]
    public void TheDirectory_IsCreatedOnFirstUse()
    {
        // A fresh install has no ~/.mcp-guardrails; the default path must work.
        Assert.False(Directory.Exists(_directory));

        using var store = Open();

        Assert.True(File.Exists(DbPath));
    }

    [Fact]
    public void TwoStoresOnOneFile_ShareOneBudget()
    {
        // Two proxies side by side draw from the same day, or four parallel
        // sessions would get four days' worth.
        using var a = Open(maxCost: 10);
        using var b = Open(maxCost: 10);

        Assert.True(a.TryCharge(6).Allowed);

        var refused = b.TryCharge(5);

        Assert.False(refused.Allowed);
        Assert.Equal(BudgetDimension.Cost, refused.Exceeded);
        Assert.Equal(6, refused.Used);
        Assert.Equal(10, refused.Cap);
        Assert.Equal(5, refused.Requested);
    }

    // ---------------------------------------------------------- the UTC day

    [Fact]
    public void ANewUtcDay_StartsFromZero()
    {
        using var store = Open(maxCalls: 1);

        Assert.True(store.TryCharge(1).Allowed);
        Assert.False(store.TryCharge(1).Allowed);

        _clock.Now = new DateTimeOffset(2026, 10, 2, 0, 0, 0, TimeSpan.Zero);

        Assert.Equal(0, store.Calls);
        Assert.True(store.TryCharge(1).Allowed);
    }

    [Fact]
    public void TheDay_IsUtcWhateverTheOffsetOfTheClock()
    {
        // 23:30 at UTC-5 is already 04:30 the next day in UTC. The window follows
        // UTC, so a local clock or a travelling laptop cannot shift it.
        using var store = Open(maxCalls: 1);

        _clock.Now = new DateTimeOffset(2026, 10, 1, 18, 0, 0, TimeSpan.Zero);
        Assert.True(store.TryCharge(1).Allowed);

        _clock.Now = new DateTimeOffset(2026, 10, 1, 23, 30, 0, TimeSpan.FromHours(-5));
        Assert.True(store.TryCharge(1).Allowed);
    }

    [Fact]
    public void TheSystemClock_IsTheDefault()
    {
        using var store = new SqliteBudgetStore(DbPath, new BudgetLimits { MaxCalls = 1 });

        Assert.True(store.TryCharge(1).Allowed);
        Assert.Equal(1, store.Calls);
    }

    // --------------------------------------------------------- the arithmetic

    [Fact]
    public void WithoutLimits_ItCountsButNeverRefuses()
    {
        using var store = new SqliteBudgetStore(DbPath, clock: _clock);

        for (var i = 0; i < 20; i++)
        {
            Assert.True(store.TryCharge(5).Allowed);
        }

        Assert.Equal(20, store.Calls);
        Assert.Equal(100, store.Cost);
    }

    [Fact]
    public void ARefusedCall_SpendsNothing()
    {
        using var store = Open(maxCost: 10);

        store.TryCharge(9);
        Assert.False(store.TryCharge(5).Allowed);

        Assert.Equal(9, store.Cost);
        Assert.Equal(1, store.Calls);
        Assert.True(store.TryCharge(1).Allowed);
    }

    [Fact]
    public void UncappedTotals_SaturateInsteadOfBecomingReal()
    {
        // SQLite would turn an overflowing integer sum into a REAL; the store
        // computes the total itself and keeps it a saturated integer.
        using var store = new SqliteBudgetStore(DbPath, clock: _clock);

        Assert.True(store.TryCharge(long.MaxValue).Allowed);
        Assert.True(store.TryCharge(long.MaxValue).Allowed);

        Assert.Equal(long.MaxValue, store.Cost);
    }

    // ----------------------------------------------------------- concurrency

    [Fact]
    public void ConcurrentCallsOnOneStore_CannotOvershootTheCap()
    {
        using var store = Open(maxCost: 10);
        var allowed = 0;

        Parallel.For(0, 64, _ =>
        {
            if (store.TryCharge(1).Allowed)
            {
                Interlocked.Increment(ref allowed);
            }
        });

        Assert.Equal(10, allowed);
        Assert.Equal(10, store.Cost);
    }

    [Fact]
    public void ConcurrentCallsAcrossConnections_CannotOvershootTheCap()
    {
        // The cross-process case, approximated by separate connections to one
        // file: only the database's own write lock (BEGIN IMMEDIATE) serialises
        // them, so this is what proves the check and the charge are one step.
        var stores = Enumerable.Range(0, 4).Select(_ => Open(maxCalls: 25)).ToArray();
        var allowed = 0;

        try
        {
            Parallel.For(0, 100, new ParallelOptions { MaxDegreeOfParallelism = 8 }, i =>
            {
                if (stores[i % stores.Length].TryCharge(1).Allowed)
                {
                    Interlocked.Increment(ref allowed);
                }
            });
        }
        finally
        {
            foreach (var store in stores)
            {
                store.Dispose();
            }
        }

        Assert.Equal(25, allowed);

        using var check = Open();
        Assert.Equal(25, check.Calls);
    }

    // ---------------------------------------------------------------- setup

    [Fact]
    public void AnInMemoryDatabase_WorksWithoutTouchingTheDisk()
    {
        using var store = new SqliteBudgetStore(":memory:", new BudgetLimits { MaxCalls = 1 }, _clock);

        Assert.True(store.TryCharge(1).Allowed);
        Assert.False(store.TryCharge(1).Allowed);
        Assert.False(Directory.Exists(_directory));
    }

    [Fact]
    public void AFileThatIsNotADatabase_FailsAtStartup()
    {
        // Fails when the proxy starts, not on the first call - and the store
        // does not leak the half-open connection on the way out.
        Directory.CreateDirectory(_directory);
        File.WriteAllText(DbPath, "this is not a sqlite database, it is a text file of sufficient length");

        Assert.Throws<SqliteException>(() => Open());
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void ABlankPath_IsRejected(string path)
    {
        Assert.Throws<ArgumentException>(() => new SqliteBudgetStore(path));
    }

    [Fact]
    public void ANegativeCost_IsRejected()
    {
        using var store = Open();

        Assert.Throws<ArgumentOutOfRangeException>(() => store.TryCharge(-1));
    }

    private sealed class FakeClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => Now;
    }
}
