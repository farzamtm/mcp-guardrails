namespace McpGuardrails.Core.Budget;

/// <summary>
/// Budget counters for the lifetime of this process.
/// </summary>
/// <remarks>
/// Right for a session budget and only for a session budget: an stdio proxy is
/// spawned per client session, so "this process" and "this session" are the same
/// thing. A daily cap needs the persistent store that lands behind
/// <see cref="IBudgetStore"/> in a later step; until then
/// <see cref="BudgetPolicy.Validate"/> refuses to accept one.
/// </remarks>
public sealed class InMemoryBudgetStore : IBudgetStore
{
    // A plain lock, not Interlocked. The two counters have to move together and
    // be compared against their caps in the same breath - that is a transaction,
    // not two atomic increments, and lock-free code that "mostly" holds a budget
    // is worse than a lock on a path that runs a few times a second.
    private readonly Lock _gate = new();
    private readonly BudgetLimits? _limits;

    private long _calls;
    private long _cost;

    /// <param name="limits">The caps to enforce, or null for no cap at all.</param>
    public InMemoryBudgetStore(BudgetLimits? limits = null)
    {
        _limits = limits;
    }

    /// <inheritdoc />
    public long Calls
    {
        get
        {
            lock (_gate)
            {
                return _calls;
            }
        }
    }

    /// <inheritdoc />
    public long Cost
    {
        get
        {
            lock (_gate)
            {
                return _cost;
            }
        }
    }

    /// <inheritdoc />
    public BudgetCharge TryCharge(long cost)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(cost);

        lock (_gate)
        {
            if (_limits?.MaxCalls is { } maxCalls && _calls >= maxCalls)
            {
                return new BudgetCharge(
                    Allowed: false,
                    Exceeded: BudgetDimension.Calls,
                    Requested: 1,
                    Used: _calls,
                    Cap: maxCalls);
            }

            if (_limits?.MaxCost is { } maxCost && WouldExceed(_cost, cost, maxCost))
            {
                return new BudgetCharge(
                    Allowed: false,
                    Exceeded: BudgetDimension.Cost,
                    Requested: cost,
                    Used: _cost,
                    Cap: maxCost);
            }

            _calls++;
            _cost = Saturating(_cost, cost);

            return BudgetCharge.Accepted;
        }
    }

    /// <remarks>
    /// Written as a subtraction rather than <c>used + cost &gt; cap</c> because the
    /// addition can overflow, and a budget that wraps past long.MaxValue into a
    /// negative number would report itself as freshly empty - an overflow bug that
    /// unlocks spending is not one to leave to chance.
    ///
    /// The subtraction is safe in the other direction because nothing is ever
    /// charged past the cap, so <c>used &lt;= cap</c> and <c>cap - used</c> cannot
    /// go negative.
    /// </remarks>
    private static bool WouldExceed(long used, long cost, long cap) => cost > cap - used;

    /// <remarks>
    /// Only reachable with no cost cap configured, where the totals are a
    /// statistic rather than a limit: clamping keeps them monotonic instead of
    /// letting them wrap negative.
    /// </remarks>
    private static long Saturating(long used, long cost) =>
        cost > long.MaxValue - used ? long.MaxValue : used + cost;
}
