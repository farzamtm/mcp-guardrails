using System.Globalization;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Budget;

/// <summary>
/// Charges an allowed call against the budget, and refuses it when the budget is
/// gone.
/// </summary>
/// <remarks>
/// Runs after the policy evaluator and before the call is forwarded, which is the
/// only ordering that makes sense: a call the policy refuses never happened, so
/// it must not spend anything, and a call that is going to be forwarded must be
/// charged before it leaves rather than after it returns.
///
/// The gate holds no counters of its own - that is the store's job - so it stays
/// a pure translation from "the arithmetic said no" into a sentence the model can
/// act on.
/// </remarks>
public sealed class BudgetGate
{
    private readonly IBudgetStore _store;
    private readonly string _scope;

    /// <param name="store">Where the running totals live.</param>
    /// <param name="scope">
    /// The scope name used in refusals, matching the policy file (<c>session</c>).
    /// </param>
    public BudgetGate(IBudgetStore store, string scope = "session")
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);

        _store = store;
        _scope = scope;
    }

    /// <summary>A gate over an unlimited store: charges nothing away, refuses nothing.</summary>
    /// <remarks>
    /// The shape an empty policy file takes. Keeping a real gate here rather than
    /// a null one means the call path is identical whether or not budgets are
    /// configured, so the configured path is not the one that only runs in
    /// production.
    /// </remarks>
    public static BudgetGate Unlimited { get; } = new(new InMemoryBudgetStore());

    /// <summary>The totals so far, for logging and tests.</summary>
    public IBudgetStore Store => _store;

    /// <summary>
    /// Applies the budget to a decision the policy already made.
    /// </summary>
    /// <returns>
    /// The original decision when the call fits the budget (or was already
    /// blocked), otherwise a denial explaining which cap ran out.
    /// </returns>
    public Decision Apply(Decision decision)
    {
        ArgumentNullException.ThrowIfNull(decision);

        // Already refused by policy: nothing is forwarded, so nothing is spent.
        // Checking this here rather than at the call site keeps "a denied call is
        // free" a property of the gate instead of a convention callers have to
        // remember.
        if (decision.IsBlocked)
        {
            return decision;
        }

        var charge = _store.TryCharge(decision.Cost);

        return charge.Allowed ? decision : Refuse(charge, decision);
    }

    private Decision Refuse(BudgetCharge charge, Decision decision) => new(
        Verdict.Deny,
        Explain(charge),
        $"{_scope}.{LimitName(charge.Exceeded)}",
        decision.Trail is null ? null : [.. decision.Trail, $"budget '{_scope}': exhausted -> deny"])
    {
        Source = DecisionSource.Budget,
        Cost = decision.Cost,
    };

    private static string LimitName(BudgetDimension? dimension) => dimension switch
    {
        BudgetDimension.Cost => "max_cost",
        _ => "max_calls",
    };

    /// <remarks>
    /// Written for the model, and specifically written to stop it retrying. A
    /// budget denial is not "try something else" like a policy denial - nothing
    /// the agent does next will work - so the message says the session is done
    /// and who can change that, and gives the numbers so a human reading the
    /// transcript can tell whether the cap was too tight.
    /// </remarks>
    private string Explain(BudgetCharge charge) => charge.Exceeded switch
    {
        BudgetDimension.Cost =>
            $"this call costs {Number(charge.Requested)} and the {_scope} has already spent " +
            $"{Number(charge.Used)} of its {Number(charge.Cap)} budget. Stop calling tools and " +
            "tell the user the budget is exhausted; only they can raise " +
            $"'budgets.{_scope}.max_cost' or start a new session.",
        _ =>
            $"the {_scope} has made {Number(charge.Used)} tool calls, which is its limit of " +
            $"{Number(charge.Cap)}. Stop calling tools and tell the user the budget is " +
            $"exhausted; only they can raise 'budgets.{_scope}.max_calls' or start a new session.",
    };

    /// <remarks>
    /// InvariantCulture, not the ambient one. This string is read by a model and
    /// by a log reader who may be anywhere; a thousands separator that changes
    /// with the operator's locale makes the audit log harder to grep for no gain.
    /// </remarks>
    private static string Number(long value) => value.ToString(CultureInfo.InvariantCulture);
}
