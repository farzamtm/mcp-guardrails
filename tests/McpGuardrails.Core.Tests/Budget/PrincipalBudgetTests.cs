using McpGuardrails.Core.Budget;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Budget;

/// <summary><c>budgets.principal</c>: one cap per authenticated caller.</summary>
public sealed class PrincipalBudgetTests
{
    private static readonly BudgetLimits _two = new() { MaxCalls = 2 };

    private static Decision Allowed(long cost = 1) => new Decision(Verdict.Allow, "test") { Cost = cost };

    [Fact]
    public void EachPrincipal_HasTheirOwnCounter()
    {
        var gate = new BudgetGate(new PrincipalBudgetStore(_two));

        Assert.False(gate.Apply(Allowed(), principal: "alice").IsBlocked);
        Assert.False(gate.Apply(Allowed(), principal: "alice").IsBlocked);

        var third = gate.Apply(Allowed(), principal: "alice");
        Assert.True(third.IsBlocked);
        Assert.Equal("principal.max_calls", third.RuleName);
        Assert.Contains("resets when the proxy restarts", third.Reason, StringComparison.Ordinal);

        Assert.False(gate.Apply(Allowed(), principal: "bob").IsBlocked);
    }

    [Fact]
    public void ACostCap_IsExplainedPerPrincipal()
    {
        var gate = new BudgetGate(new PrincipalBudgetStore(new BudgetLimits { MaxCost = 3 }));

        gate.Apply(Allowed(cost: 3), principal: "alice");
        var refused = gate.Apply(Allowed(cost: 1), principal: "alice");

        Assert.Equal("principal.max_cost", refused.RuleName);
        Assert.Contains("'budgets.principal.max_cost'", refused.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ACallWithNoPrincipal_IsRefused_NotWavedThrough()
    {
        var gate = new BudgetGate(new PrincipalBudgetStore(_two));

        var refused = gate.Apply(Allowed());

        Assert.True(refused.IsBlocked);
        Assert.Equal("principal.unidentified", refused.RuleName);
    }

    [Fact]
    public void WithADailyCap_BothApply_AndARefusedDayRefundsThePrincipal()
    {
        var daily = new InMemoryBudgetStore(new BudgetLimits { MaxCalls = 1 });
        var principals = new PrincipalBudgetStore(_two);
        var gate = new BudgetGate(principals, daily);

        Assert.False(gate.Apply(Allowed(), principal: "alice").IsBlocked);

        var refused = gate.Apply(Allowed(), principal: "alice");
        Assert.Equal("daily.max_calls", refused.RuleName);
        Assert.Equal(1, principals.For("alice").Calls);
        Assert.Same(daily, gate.DailyStore);
        Assert.Same(daily, gate.Store);
    }

    [Fact]
    public void WithADailyCap_ThePrincipalCapStillRefusesFirst()
    {
        var gate = new BudgetGate(
            new PrincipalBudgetStore(new BudgetLimits { MaxCalls = 1 }),
            new InMemoryBudgetStore(new BudgetLimits { MaxCalls = 10 }));

        gate.Apply(Allowed(), principal: "alice");

        Assert.Equal("principal.max_calls", gate.Apply(Allowed(), principal: "alice").RuleName);
    }

    [Fact]
    public void BlockedAndUnresolvedCalls_AreFree()
    {
        var principals = new PrincipalBudgetStore(_two);
        var gate = new BudgetGate(principals);

        gate.Apply(new Decision(Verdict.Deny, "no"), principal: "alice");
        gate.Apply(Allowed(), toolResolved: false, principal: "alice");

        Assert.Equal(0, principals.For("alice").Calls);
    }

    [Fact]
    public void For_BuildsAPrincipalGate_FromThePolicy()
    {
        var document = PolicyLoader.Parse("""
            access:
              oauth:
                issuer: https://login.example.com
                audience: api://x
            budgets:
              principal: { max_calls: 1 }
              daily: { max_calls: 10 }
            """);
        IBudgetStore? opened = null;

        var gate = BudgetGate.For(document.EffectiveBudgets, limits => opened = new InMemoryBudgetStore(limits));

        Assert.NotNull(opened);
        gate.Apply(Allowed(), principal: "alice");
        Assert.Equal("principal.max_calls", gate.Apply(Allowed(), principal: "alice").RuleName);
    }

    [Fact]
    public void For_WithOnlyAPrincipalCap_OpensNoDailyStore()
    {
        var gate = BudgetGate.For(
            new BudgetPolicy { Principal = _two },
            _ => throw new InvalidOperationException("no daily store wanted"));

        Assert.Null(gate.DailyStore);
    }

    [Fact]
    public void SessionAndPrincipal_CannotBothBeSet()
    {
        var message = Assert.Throws<PolicyException>(
            () => new BudgetPolicy { Session = _two, Principal = _two }.Validate()).Message;

        Assert.Contains("cannot both be set", message, StringComparison.Ordinal);
    }

    [Fact]
    public void APrincipalCapWithNoLimits_IsRefused()
    {
        var message = Assert.Throws<PolicyException>(
            () => new BudgetPolicy { Principal = new BudgetLimits() }.Validate()).Message;

        Assert.Contains("'budgets.principal' sets no limits", message, StringComparison.Ordinal);
    }

    [Fact]
    public void APrincipalCap_MakesTheSectionNonEmpty()
    {
        Assert.False(new BudgetPolicy { Principal = _two }.IsEmpty);
    }

    [Fact]
    public void TheStore_RejectsNulls()
    {
        Assert.Throws<ArgumentNullException>(() => new PrincipalBudgetStore(null!));
        Assert.Throws<ArgumentNullException>(() => new PrincipalBudgetStore(_two).For(null!));
    }
}
