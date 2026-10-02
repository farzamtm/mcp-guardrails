namespace McpGuardrails.Core.Budget;

/// <summary>
/// Budget counters for the lifetime of this process.
/// </summary>
/// <remarks>
/// Right for a session budget and only for a session budget: an stdio proxy is
/// spawned per client session, so "this process" and "this session" are the same
/// thing. Daily caps live in <see cref="SqliteBudgetStore"/>, because a day
/// outlives any one process.
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
            var charge = BudgetArithmetic.Check(_limits, _calls, _cost, cost);

            if (charge.Allowed)
            {
                _calls++;
                _cost = BudgetArithmetic.Saturating(_cost, cost);
            }

            return charge;
        }
    }

    /// <summary>
    /// Gives back one call of <paramref name="cost"/> that an earlier
    /// <see cref="TryCharge"/> accepted.
    /// </summary>
    /// <remarks>
    /// Exists for exactly one caller: <see cref="BudgetGate"/>, when the session
    /// accepted a call that the daily cap then refused. The call never went out,
    /// so the session must not pay for it.
    ///
    /// Deliberately on this class and not on <see cref="IBudgetStore"/>. Undoing
    /// a charge is only safe on a store nobody else can see: a refund against the
    /// shared SQLite file would be visible to other proxies in between, and
    /// across midnight would credit a day that was never charged.
    ///
    /// Clamped at zero, so a refund that does not match a charge cannot turn
    /// into extra budget.
    /// </remarks>
    internal void Refund(long cost)
    {
        lock (_gate)
        {
            _calls = Math.Max(0, _calls - 1);
            _cost = Math.Max(0, _cost - cost);
        }
    }
}
