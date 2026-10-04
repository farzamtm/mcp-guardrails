using System.Globalization;
using System.Runtime.CompilerServices;
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

    /// <summary>The scope name for the per-caller budget.</summary>
    public const string PrincipalScope = "principal";

    private readonly IBudgetStore _store;
    private readonly string _scope;

    // Set only when a session and a daily cap are configured together. See
    // ApplyBoth for why the session has to be the concrete in-memory store
    // rather than any IBudgetStore.
    private readonly InMemoryBudgetStore? _session;
    private readonly IBudgetStore? _daily;

    // Set only for per-principal budgets, which pick their in-memory store per
    // call and otherwise follow the session's rules, including with a daily cap.
    private readonly PrincipalBudgetStore? _principals;

    // One pairing per in-memory store charged before the daily store: the
    // session's single store, or each principal's own. Per store rather than one
    // for the gate, because a caller at its own cap can only be freed by a refund
    // to that same store - waiting on other callers' charges would hold a
    // request thread for traffic that can never give it budget back. Weak keys,
    // so a pairing lives exactly as long as its store.
    private readonly ConditionalWeakTable<InMemoryBudgetStore, Pairing> _pairings = new();

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

    /// <summary>A gate enforcing a budget per caller, and a daily budget if given.</summary>
    /// <param name="principals">The per-principal counters.</param>
    /// <param name="daily">The per-day counters, or null for no daily cap.</param>
    public BudgetGate(PrincipalBudgetStore principals, IBudgetStore? daily = null)
        : this(daily ?? new InMemoryBudgetStore(), daily is null ? PrincipalScope : DailyScope)
    {
        ArgumentNullException.ThrowIfNull(principals);

        _principals = principals;
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

        // Principal and session never come together: BudgetPolicy.Validate
        // refuses the pair, because no transport could enforce both.
        if (budgets.Principal is { } principal)
        {
            return new BudgetGate(
                new PrincipalBudgetStore(principal),
                budgets.Daily is { } perDay ? openDaily(perDay) : null);
        }

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
    /// <remarks>
    /// The session store when both scopes are configured; with per-principal
    /// budgets, the daily store, or an unlimited one when there is none.
    /// </remarks>
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
    /// <param name="principal">
    /// Who made the call, for per-principal budgets. Ignored otherwise.
    /// </param>
    /// <returns>
    /// The original decision when the call fits the budget (or was already
    /// blocked, or names no known tool), otherwise a denial explaining which cap
    /// ran out.
    /// </returns>
    public Decision Apply(Decision decision, bool toolResolved = true, string? principal = null)
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

        if (_principals is not null)
        {
            return ApplyPrincipal(decision, _principals, principal);
        }

        if (_session is not null && _daily is not null)
        {
            return ApplyBoth(decision, _session, SessionScope, _daily);
        }

        return ApplyOne(decision, _store, _scope);
    }

    private static Decision ApplyOne(Decision decision, IBudgetStore store, string scope)
    {
        if (TryCharge(store, decision.Cost, out var charge) is { } failure)
        {
            return Unavailable(decision, scope, failure);
        }

        return charge.Allowed ? decision : Refuse(charge, decision, scope);
    }

    /// <remarks>
    /// A call with no principal under a per-principal budget is refused rather
    /// than waved through: it cannot happen through the HTTP listener, which
    /// rejects a request without a valid token, so reaching it means the gate is
    /// wired wrong - and an uncharged call is a cap that does not hold.
    /// </remarks>
    private Decision ApplyPrincipal(Decision decision, PrincipalBudgetStore principals, string? principal)
    {
        if (principal is null)
        {
            return decision.RefusedBy(
                DecisionSource.Budget,
                $"{PrincipalScope}.unidentified",
                "the call carries no authenticated principal, so the per-principal budget cannot be " +
                "charged and the call is refused. Stop calling tools and tell the user the guardrails " +
                "proxy is misconfigured.",
                $"budget '{PrincipalScope}': no principal -> deny");
        }

        var own = principals.For(principal);

        return _daily is not null
            ? ApplyBoth(decision, own, PrincipalScope, _daily)
            : ApplyOne(decision, own, PrincipalScope);
    }

    /// <remarks>
    /// Two stores cannot be charged in one atomic step, so the order does the
    /// work. The session goes first because it is private to this process and
    /// can be undone exactly. The daily store goes last because it is shared
    /// with other proxies and cannot be: whatever it decides is final, so it
    /// never needs undoing. If the day refuses or fails, the session charge is
    /// handed back.
    ///
    /// The daily charge is a SQLite write transaction that can wait seconds for
    /// another proxy's write lock, so no in-process lock is held across it -
    /// otherwise one slow disk write would queue every other call in this
    /// process behind it, including calls the session cap would refuse at once.
    ///
    /// That leaves one window to close. Between a call's session charge and its
    /// refund, a concurrent call on the same store could see it full and be
    /// refused for budget that was never really spent. So a refusal while other
    /// charges against that store are still pending is not final: the caller
    /// waits for them to settle and tries again, and is refused only once
    /// nothing is in flight. Only a call already at its cap ever waits, and only
    /// on charges against its own store - for per-principal budgets, the other
    /// callers' traffic never delays a refusal. Neither cap can be overshot
    /// either way: each store's own check-and-charge is atomic, and a refund
    /// only returns a charge this call made.
    /// </remarks>
    private Decision ApplyBoth(Decision decision, InMemoryBudgetStore session, string sessionScope, IBudgetStore daily)
    {
        var pairing = _pairings.GetValue(session, static _ => new Pairing());

        lock (pairing)
        {
            while (true)
            {
                var sessionCharge = session.TryCharge(decision.Cost);

                if (sessionCharge.Allowed)
                {
                    pairing.Pending++;
                    break;
                }

                if (pairing.Pending == 0)
                {
                    return Refuse(sessionCharge, decision, sessionScope);
                }

                Monitor.Wait(pairing);
            }
        }

        var failure = TryCharge(daily, decision.Cost, out var dailyCharge);

        lock (pairing)
        {
            // Refunded inside the same lock that decrements Pending, so a waiter
            // that wakes up sees the refund and the settled count together.
            if (failure is not null || !dailyCharge.Allowed)
            {
                session.Refund(decision.Cost);
            }

            pairing.Pending--;
            Monitor.PulseAll(pairing);
        }

        if (failure is not null)
        {
            return Unavailable(decision, DailyScope, failure);
        }

        return dailyCharge.Allowed ? decision : Refuse(dailyCharge, decision, DailyScope);
    }

    /// <remarks>
    /// A store that throws - SQLite busy past its timeout, a full disk, a
    /// corrupt file - is turned into a refusal here rather than allowed to
    /// escape. Failing closed is the point of the daily store, and a refusal is
    /// the closed state the rest of the pipeline already understands: it is
    /// recorded in the audit log with a reason and reaches the model as a
    /// readable tool error, where an exception would surface as a protocol
    /// error and leave the audit line without a decision.
    ///
    /// Every exception, not only SqliteException: the store is an interface,
    /// and whatever broke it, a budget that cannot be checked must not let the
    /// call through.
    /// </remarks>
    /// <returns>Null when the store answered, otherwise what it threw.</returns>
    private static Exception? TryCharge(IBudgetStore store, long cost, out BudgetCharge charge)
    {
        try
        {
            charge = store.TryCharge(cost);
            return null;
        }
        catch (Exception ex)
        {
            // Never read: the caller checks the returned failure first.
            charge = BudgetCharge.Accepted;
            return ex;
        }
    }

    /// <remarks>
    /// Built on the incoming decision, so a call a human approved and the budget
    /// then refused still says so in the audit log and the approvals counter.
    /// </remarks>
    private static Decision Refuse(BudgetCharge charge, Decision decision, string scope) =>
        decision.RefusedBy(
            DecisionSource.Budget,
            $"{scope}.{LimitName(charge.Exceeded)}",
            Explain(charge, scope),
            $"budget '{scope}': exhausted -> deny");

    /// <remarks>
    /// Says the budget could not be checked rather than that it ran out: the
    /// operator has a broken store to fix, and the model should stop instead of
    /// retrying into the same failure. The exception type and message are for
    /// the operator reading the audit log; a store error carries no tool
    /// arguments, so nothing the agent sent is replayed.
    /// </remarks>
    private static Decision Unavailable(Decision decision, string scope, Exception failure) =>
        decision.RefusedBy(
            DecisionSource.Budget,
            $"{scope}.unavailable",
            $"the {scope} budget could not be checked ({failure.GetType().Name}: {failure.Message}), " +
            "so the call is refused rather than let through unmetered. Stop calling tools and " +
            "tell the user the guardrails budget store is failing.",
            $"budget '{scope}': store failed -> deny");

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
        (PrincipalScope, BudgetDimension.Cost) =>
            $"this call costs {Number(charge.Requested)} and the identity you call as has already " +
            $"spent {Number(charge.Used)} of its {Number(charge.Cap)} budget. Stop calling tools and " +
            "tell the user the budget is exhausted; only they can raise " +
            $"'budgets.{PrincipalScope}.max_cost', otherwise it resets when the proxy restarts.",
        (PrincipalScope, _) =>
            $"the identity you call as has made {Number(charge.Used)} tool calls, which is its limit " +
            $"of {Number(charge.Cap)}. Stop calling tools and tell the user the budget is exhausted; " +
            $"only they can raise 'budgets.{PrincipalScope}.max_calls', otherwise it resets when the " +
            "proxy restarts.",
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

    /// <summary>The lock and in-flight count for one in-memory store. See ApplyBoth.</summary>
    /// <remarks>
    /// A plain class used as its own monitor rather than System.Threading.Lock,
    /// because ApplyBoth needs Monitor.Wait/PulseAll, which Lock does not offer.
    /// Never held across a call into the daily store.
    /// </remarks>
    private sealed class Pairing
    {
        /// <summary>Charges against the store whose daily charge has not settled yet.</summary>
        public int Pending;
    }
}
