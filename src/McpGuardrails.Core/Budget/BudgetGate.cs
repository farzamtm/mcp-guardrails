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
    /// <summary>The scope name for the per-process budget.</summary>
    public const string SessionScope = "session";

    /// <summary>The scope name for the per-UTC-day budget.</summary>
    public const string DailyScope = "daily";

    private readonly IBudgetStore _store;
    private readonly string _scope;

    // Set only when both scopes are configured. See ApplyBoth for why the session
    // has to be the concrete in-memory store rather than any IBudgetStore.
    private readonly InMemoryBudgetStore? _session;
    private readonly IBudgetStore? _daily;
    private readonly Lock _pair = new();

    /// <param name="store">Where the running totals live.</param>
    /// <param name="scope">
    /// The scope name used in refusals, matching the policy file
    /// (<see cref="SessionScope"/> or <see cref="DailyScope"/>).
    /// </param>
    public BudgetGate(IBudgetStore store, string scope = SessionScope)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);

        _store = store;
        _scope = scope;
    }

    /// <summary>A gate enforcing a session budget and a daily budget together.</summary>
    /// <param name="session">The per-process counters.</param>
    /// <param name="daily">The per-day counters, normally a <see cref="SqliteBudgetStore"/>.</param>
    public BudgetGate(InMemoryBudgetStore session, IBudgetStore daily)
        : this(session)
    {
        ArgumentNullException.ThrowIfNull(daily);

        _session = session;
        _daily = daily;
    }

    /// <summary>Builds the gate a policy file's <c>budgets:</c> section asks for.</summary>
    /// <param name="budgets">The validated budget section.</param>
    /// <param name="openDaily">
    /// Opens the persistent daily store. Only called when a daily cap is
    /// configured, so a policy without one never creates a database file.
    /// </param>
    /// <remarks>
    /// Lives here rather than in the CLI so all four combinations are covered by
    /// unit tests instead of only by the smoke run.
    /// </remarks>
    public static BudgetGate For(BudgetPolicy budgets, Func<BudgetLimits, IBudgetStore> openDaily)
    {
        ArgumentNullException.ThrowIfNull(budgets);
        ArgumentNullException.ThrowIfNull(openDaily);

        return (budgets.Session, budgets.Daily) switch
        {
            ({ } session, { } daily) => new BudgetGate(new InMemoryBudgetStore(session), openDaily(daily)),
            ({ } session, null) => new BudgetGate(new InMemoryBudgetStore(session)),
            (null, { } daily) => new BudgetGate(openDaily(daily), DailyScope),
            _ => Unlimited,
        };
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
    /// <remarks>The session store when both scopes are configured.</remarks>
    public IBudgetStore Store => _store;

    /// <summary>The daily store when both scopes are configured, otherwise null.</summary>
    public IBudgetStore? DailyStore => _daily;

    /// <summary>
    /// Applies the budget to a decision the policy already made.
    /// </summary>
    /// <param name="decision">What policy, scanning and approval decided.</param>
    /// <param name="toolResolved">
    /// Whether the tool name resolved to a downstream server. False means the
    /// call handler is going to answer "unknown tool" without forwarding
    /// anything, so the call is not charged. Defaults to true, so a caller that
    /// does not say is charged - the safe direction for a bound.
    /// </param>
    /// <returns>
    /// The original decision when the call fits the budget (or was already
    /// blocked, or names no known tool), otherwise a denial explaining which cap
    /// ran out.
    /// </returns>
    public Decision Apply(Decision decision, bool toolResolved = true)
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

        // Same reasoning for a tool no downstream server owns: nothing is
        // forwarded, so nothing is spent, and the budget measures work done
        // rather than typos. It does mean an agent looping on an unknown name is
        // not stopped by the budget. That is acceptable: every such call ends at
        // the proxy's own "unknown tool" error without touching a downstream
        // system, and it is still evaluated by policy and written to the audit
        // log. Skipped rather than charged and refunded, so a concurrent call can
        // never be refused for budget that was only spent for a moment.
        if (!toolResolved)
        {
            return decision;
        }

        if (_session is not null && _daily is not null)
        {
            return ApplyBoth(decision, _session, _daily);
        }

        var charge = _store.TryCharge(decision.Cost);

        return charge.Allowed ? decision : Refuse(charge, decision, _scope);
    }

    /// <remarks>
    /// Two stores cannot be charged in one atomic step, so the order does the
    /// work. The session goes first because it is private to this process and
    /// can be undone exactly. The daily store goes last because it is shared
    /// with other proxies and cannot be: whatever it decides is final, so it
    /// never needs undoing. If the day refuses, the session charge is handed back.
    ///
    /// The lock stops another call in this process from seeing the session
    /// charge in the moment before it is refunded, which would refuse that call
    /// for budget that was never really spent.
    /// </remarks>
    private Decision ApplyBoth(Decision decision, InMemoryBudgetStore session, IBudgetStore daily)
    {
        lock (_pair)
        {
            var sessionCharge = session.TryCharge(decision.Cost);

            if (!sessionCharge.Allowed)
            {
                return Refuse(sessionCharge, decision, SessionScope);
            }

            BudgetCharge dailyCharge;
            try
            {
                dailyCharge = daily.TryCharge(decision.Cost);
            }
            catch
            {
                // The database failed, so the call fails and is not forwarded -
                // and a call that did not go out must not cost the session.
                session.Refund(decision.Cost);
                throw;
            }

            if (dailyCharge.Allowed)
            {
                return decision;
            }

            session.Refund(decision.Cost);

            return Refuse(dailyCharge, decision, DailyScope);
        }
    }

    private static Decision Refuse(BudgetCharge charge, Decision decision, string scope) => new(
        Verdict.Deny,
        Explain(charge, scope),
        $"{scope}.{LimitName(charge.Exceeded)}",
        decision.Trail is null ? null : [.. decision.Trail, $"budget '{scope}': exhausted -> deny"])
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
    /// the agent does next will work - so the message says the budget is done
    /// and who can change that, and gives the numbers so a human reading the
    /// transcript can tell whether the cap was too tight.
    ///
    /// The daily wording names UTC and the reset, because "start a new session"
    /// is precisely the advice that does not help against a daily cap.
    /// </remarks>
    private static string Explain(BudgetCharge charge, string scope) => (scope, charge.Exceeded) switch
    {
        (DailyScope, BudgetDimension.Cost) =>
            $"this call costs {Number(charge.Requested)} and {Number(charge.Used)} of today's " +
            $"{Number(charge.Cap)} budget is already spent (days are UTC). Stop calling tools " +
            "and tell the user the daily budget is exhausted; only they can raise " +
            "'budgets.daily.max_cost', otherwise it resets at 00:00 UTC.",
        (DailyScope, _) =>
            $"{Number(charge.Used)} tool calls have been made today (UTC), which is the daily " +
            $"limit of {Number(charge.Cap)}. Stop calling tools and tell the user the daily " +
            "budget is exhausted; only they can raise 'budgets.daily.max_calls', otherwise " +
            "it resets at 00:00 UTC.",
        (_, BudgetDimension.Cost) =>
            $"this call costs {Number(charge.Requested)} and the {scope} has already spent " +
            $"{Number(charge.Used)} of its {Number(charge.Cap)} budget. Stop calling tools and " +
            "tell the user the budget is exhausted; only they can raise " +
            $"'budgets.{scope}.max_cost' or start a new session.",
        _ =>
            $"the {scope} has made {Number(charge.Used)} tool calls, which is its limit of " +
            $"{Number(charge.Cap)}. Stop calling tools and tell the user the budget is " +
            $"exhausted; only they can raise 'budgets.{scope}.max_calls' or start a new session.",
    };

    /// <remarks>
    /// InvariantCulture, not the ambient one. This string is read by a model and
    /// by a log reader who may be anywhere; a thousands separator that changes
    /// with the operator's locale makes the audit log harder to grep for no gain.
    /// </remarks>
    private static string Number(long value) => value.ToString(CultureInfo.InvariantCulture);
}
