using System.Globalization;
using Microsoft.Data.Sqlite;

namespace McpGuardrails.Core.Budget;

/// <summary>
/// Daily budget counters kept in a SQLite file, so a cap holds across proxy
/// restarts and across proxies running side by side.
/// </summary>
/// <remarks>
/// An stdio proxy lives for one client session, so a daily cap kept in memory
/// would reset every time the client reconnected - a limit an agent defeats by
/// being restarted. The counters have to live somewhere that outlives the
/// process, and be shared by every process charging the same budget.
///
/// <para><b>The day is UTC.</b> Every window runs from 00:00 to 24:00 UTC. A
/// configurable time zone was considered and rejected: local days are 23 or 25
/// hours long twice a year, local midnight can be ambiguous, and two machines
/// sharing one file in different zones would disagree about which row is
/// "today". UTC makes the window a pure function of the clock, and the refusal
/// says UTC so nobody has to guess.</para>
///
/// <para><b>One file is one budget.</b> Every proxy pointed at the same file
/// draws from the same daily counters, which is the point: four parallel
/// sessions do not get four days' worth. Give a different agent a different
/// file to give it a separate budget.</para>
///
/// <para><b>Failures fail closed.</b> A database error is thrown, not swallowed,
/// so the call is not forwarded. A budget that waves calls through when its
/// storage breaks is the failure mode this class exists to prevent.</para>
/// </remarks>
public sealed class SqliteBudgetStore : IBudgetStore, IDisposable
{
    // The table is generic over "period" rather than hard-wired to days so a
    // weekly or monthly window is a new key prefix, not a migration.
    private const string _schema = """
        CREATE TABLE IF NOT EXISTS budget_spend (
            period TEXT    NOT NULL PRIMARY KEY,
            calls  INTEGER NOT NULL,
            cost   INTEGER NOT NULL
        ) STRICT;
        """;

    private const string _inMemory = ":memory:";

    // Serialises use of the one connection within this process. SqliteConnection
    // is not thread-safe, and the transaction below already makes concurrent
    // callers wait for each other, so a connection pool would buy nothing.
    private readonly Lock _gate = new();
    private readonly SqliteConnection _connection;
    private readonly BudgetLimits? _limits;
    private readonly TimeProvider _clock;

    /// <param name="path">
    /// The database file, created with its directory if missing. <c>:memory:</c>
    /// gives a private in-memory database, which is only useful for tests.
    /// </param>
    /// <param name="limits">The daily caps to enforce, or null for no cap.</param>
    /// <param name="clock">
    /// Where "now" comes from, so tests can cross midnight without waiting for
    /// it. Defaults to the system clock.
    /// </param>
    /// <exception cref="SqliteException">The file cannot be opened or initialised.</exception>
    public SqliteBudgetStore(string path, BudgetLimits? limits = null, TimeProvider? clock = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        _limits = limits;
        _clock = clock ?? TimeProvider.System;

        if (path != _inMemory)
        {
            // A fresh install has no ~/.mcp-guardrails yet, and SQLite will not
            // create directories. Failing on the first run would be a poor first
            // impression for a default path.
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        }

        _connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,

            // One connection for the store's lifetime, so pooling only keeps the
            // file open after Dispose - which on Windows stops anyone deleting it.
            Pooling = false,
        }.ToString());

        try
        {
            _connection.Open();

            // WAL lets readers proceed while another proxy holds the write lock.
            // busy_timeout makes a second proxy wait for that lock instead of
            // failing immediately: contention here is a few milliseconds per call.
            Execute("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 30000;");
            Execute(_schema);
        }
        catch
        {
            _connection.Dispose();
            throw;
        }
    }

    /// <summary>Calls charged today (UTC).</summary>
    public long Calls => Read().Calls;

    /// <summary>Cost charged today (UTC).</summary>
    public long Cost => Read().Cost;

    /// <inheritdoc />
    /// <remarks>
    /// Read, check and write happen inside one <c>BEGIN IMMEDIATE</c>
    /// transaction. IMMEDIATE takes the database's write lock before the read,
    /// not at the first write, so two proxies cannot both read "one left" and
    /// both spend it - the second waits, then reads the first one's charge.
    /// </remarks>
    public BudgetCharge TryCharge(long cost)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(cost);

        lock (_gate)
        {
            var period = CurrentPeriod();

            using var transaction = _connection.BeginTransaction(deferred: false);

            var (calls, spent) = Select(period, transaction);
            var charge = BudgetArithmetic.Check(_limits, calls, spent, cost);

            if (charge.Allowed)
            {
                // Totals are computed here, not with `cost = cost + $cost` in SQL:
                // SQLite turns an overflowing integer sum into a REAL, and the
                // saturating add is the behaviour the in-memory store has.
                Upsert(period, calls + 1, BudgetArithmetic.Saturating(spent, cost), transaction);
            }

            // Committed even when refused, which writes nothing: it releases the
            // write lock now rather than at Dispose, and keeps one code path.
            transaction.Commit();

            return charge;
        }
    }

    /// <inheritdoc />
    public void Dispose() => _connection.Dispose();

    /// <remarks>
    /// The key carries the window kind so other periods can share the table.
    /// InvariantCulture so the key is the same on every machine: a culture with
    /// a non-Gregorian calendar would otherwise write a different "today".
    /// </remarks>
    private string CurrentPeriod() =>
        "daily:" + _clock.GetUtcNow().UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    private (long Calls, long Cost) Read()
    {
        lock (_gate)
        {
            return Select(CurrentPeriod(), transaction: null);
        }
    }

    private (long Calls, long Cost) Select(string period, SqliteTransaction? transaction)
    {
        using var command = _connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT calls, cost FROM budget_spend WHERE period = $period;";
        command.Parameters.AddWithValue("$period", period);

        using var reader = command.ExecuteReader();

        // No row yet means nothing has been charged today.
        return reader.Read() ? (reader.GetInt64(0), reader.GetInt64(1)) : (0, 0);
    }

    private void Upsert(string period, long calls, long cost, SqliteTransaction transaction)
    {
        using var command = _connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO budget_spend (period, calls, cost) VALUES ($period, $calls, $cost)
            ON CONFLICT (period) DO UPDATE SET calls = excluded.calls, cost = excluded.cost;
            """;
        command.Parameters.AddWithValue("$period", period);
        command.Parameters.AddWithValue("$calls", calls);
        command.Parameters.AddWithValue("$cost", cost);
        command.ExecuteNonQuery();
    }

    private void Execute(string sql)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }
}
