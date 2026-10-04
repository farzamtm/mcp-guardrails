using System.Collections.Concurrent;

namespace McpGuardrails.Core.Budget;

/// <summary>
/// One in-memory budget per caller, created the first time that caller is seen.
/// </summary>
/// <remarks>
/// Counters live for the process, like <c>budgets.session</c>, and are not
/// persisted: a per-day cap per caller would be <c>budgets.daily</c> keyed by
/// principal, which is a different feature. Principals come from validated
/// tokens, so the map grows with the number of real identities that called,
/// not with anything an unauthenticated client can invent.
/// </remarks>
public sealed class PrincipalBudgetStore
{
    private readonly BudgetLimits _limits;
    private readonly ConcurrentDictionary<string, InMemoryBudgetStore> _stores = new(StringComparer.Ordinal);

    /// <param name="limits">The caps every principal gets.</param>
    public PrincipalBudgetStore(BudgetLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        _limits = limits;
    }

    /// <summary>The counters for <paramref name="principal"/>.</summary>
    public InMemoryBudgetStore For(string principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return _stores.GetOrAdd(principal, static (_, limits) => new InMemoryBudgetStore(limits), _limits);
    }
}
