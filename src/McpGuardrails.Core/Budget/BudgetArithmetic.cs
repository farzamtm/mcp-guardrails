namespace McpGuardrails.Core.Budget;

/// <summary>
/// The decision every budget store makes: does one more call fit?
/// </summary>
/// <remarks>
/// Pulled out of the stores so the in-memory and SQLite implementations cannot
/// drift apart on an edge case such as overflow. The stores own atomicity (a
/// lock, a transaction); this owns the arithmetic, and is pure so it can be
/// tested without either.
/// </remarks>
internal static class BudgetArithmetic
{
    /// <summary>
    /// Checks a charge of <paramref name="cost"/> against <paramref name="limits"/>
    /// given what has already been spent.
    /// </summary>
    /// <returns>
    /// <see cref="BudgetCharge.Accepted"/> when it fits, otherwise a refusal
    /// naming the cap and carrying the numbers.
    /// </returns>
    public static BudgetCharge Check(BudgetLimits? limits, long calls, long spent, long cost)
    {
        if (limits?.MaxCalls is { } maxCalls && calls >= maxCalls)
        {
            return new BudgetCharge(
                Allowed: false,
                Exceeded: BudgetDimension.Calls,
                Requested: 1,
                Used: calls,
                Cap: maxCalls);
        }

        if (limits?.MaxCost is { } maxCost && WouldExceed(spent, cost, maxCost))
        {
            return new BudgetCharge(
                Allowed: false,
                Exceeded: BudgetDimension.Cost,
                Requested: cost,
                Used: spent,
                Cap: maxCost);
        }

        return BudgetCharge.Accepted;
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

    /// <summary>Adds a charge to a running total without wrapping.</summary>
    /// <remarks>
    /// Only reachable with no cost cap configured, where the totals are a
    /// statistic rather than a limit: clamping keeps them monotonic instead of
    /// letting them wrap negative. It also matters for SQLite specifically,
    /// whose integer addition silently turns into a floating-point value on
    /// overflow - so the store computes totals here and writes the result.
    /// </remarks>
    public static long Saturating(long used, long cost) =>
        cost > long.MaxValue - used ? long.MaxValue : used + cost;
}
