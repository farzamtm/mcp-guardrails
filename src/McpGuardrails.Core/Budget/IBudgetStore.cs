namespace McpGuardrails.Core.Budget;

/// <summary>
/// Which cap a call ran into.
/// </summary>
public enum BudgetDimension
{
    /// <summary>The number of tool calls.</summary>
    Calls,

    /// <summary>The accumulated cost of tool calls.</summary>
    Cost,
}

/// <summary>
/// The result of asking a store to charge one call against the budget.
/// </summary>
/// <param name="Allowed">True when the charge was applied and the call may proceed.</param>
/// <param name="Exceeded">Which cap refused the call, or null when allowed.</param>
/// <param name="Requested">What this call asked for: its cost, or 1 for a call count.</param>
/// <param name="Used">How much of the cap was already consumed before this call.</param>
/// <param name="Cap">The configured limit that was hit.</param>
/// <remarks>
/// A rejection carries the numbers rather than a formatted string. The store's
/// job is arithmetic; wording the refusal for the model is
/// <see cref="BudgetGate"/>'s, and keeping those apart is what lets the store be
/// tested without asserting on prose.
/// </remarks>
public sealed record BudgetCharge(
    bool Allowed,
    BudgetDimension? Exceeded = null,
    long Requested = 0,
    long Used = 0,
    long Cap = 0)
{
    /// <summary>The charge went through.</summary>
    public static BudgetCharge Accepted { get; } = new(true);
}

/// <summary>
/// Keeps the running totals a budget is enforced against.
/// </summary>
/// <remarks>
/// An interface with one implementation today, which is usually a smell - here it
/// is the seam the spec asks for. Session counters live in memory; daily counters
/// need a store that survives process exit (SQLite, per the spec), and that
/// arrives behind this same interface without the gate or the CLI noticing.
///
/// Implementations must be safe to call concurrently: nothing serialises tool
/// calls, so two calls can reach the gate at once, and a budget that can be
/// overshot by racing is not a budget.
/// </remarks>
public interface IBudgetStore
{
    /// <summary>
    /// Charges one call of <paramref name="cost"/> against the budget, if it fits.
    /// </summary>
    /// <remarks>
    /// Test-and-charge in a single operation on purpose. Splitting it into "may
    /// I?" then "I did" leaves a window where two callers both get a yes for the
    /// last unit of budget.
    ///
    /// A refused call consumes nothing: it never reached the downstream server,
    /// so charging for it would let a hard cap be drained by calls that did no
    /// work. An allowed call is charged even if the downstream server then fails
    /// - the work was attempted, and refunding failures would let a broken tool
    /// be retried without limit.
    /// </remarks>
    BudgetCharge TryCharge(long cost);

    /// <summary>Calls charged so far.</summary>
    long Calls { get; }

    /// <summary>Cost charged so far.</summary>
    long Cost { get; }
}
