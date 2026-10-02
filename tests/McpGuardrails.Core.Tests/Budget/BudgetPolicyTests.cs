using McpGuardrails.Core.Budget;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Budget;

public sealed class BudgetPolicyTests
{
    [Fact]
    public void NoSection_IsEmptyAndValid()
    {
        Assert.True(BudgetPolicy.None.IsEmpty);

        BudgetPolicy.None.Validate();
    }

    [Fact]
    public void ASessionSection_IsNotEmpty()
    {
        var budgets = new BudgetPolicy { Session = new BudgetLimits { MaxCalls = 5 } };

        Assert.False(budgets.IsEmpty);

        budgets.Validate();
    }

    [Fact]
    public void ADailySection_IsNotEmptyAndValid()
    {
        var budgets = new BudgetPolicy { Daily = new BudgetLimits { MaxCalls = 5 } };

        Assert.False(budgets.IsEmpty);

        budgets.Validate();
    }

    [Fact]
    public void ADailySection_IsValidatedLikeASessionOne()
    {
        var budgets = new BudgetPolicy { Daily = new BudgetLimits { MaxCost = -1 } };

        var error = Assert.Throws<PolicyException>(budgets.Validate);

        // Named by its own path, so the operator edits the right block.
        Assert.Contains("budgets.daily.max_cost", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ASectionWithNoLimits_IsRejected()
    {
        var budgets = new BudgetPolicy { Session = new BudgetLimits() };

        var error = Assert.Throws<PolicyException>(budgets.Validate);

        // Silence here would be a budget section that budgets nothing, which is
        // indistinguishable from a typo in the limit's name.
        Assert.Contains("budgets.session", error.Message, StringComparison.Ordinal);
        Assert.Contains("max_calls", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ANegativeCallLimit_IsRejected()
    {
        var budgets = new BudgetPolicy { Session = new BudgetLimits { MaxCalls = -1 } };

        var error = Assert.Throws<PolicyException>(budgets.Validate);

        Assert.Contains("budgets.session.max_calls", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ANegativeCostLimit_IsRejected()
    {
        var budgets = new BudgetPolicy { Session = new BudgetLimits { MaxCost = -5 } };

        var error = Assert.Throws<PolicyException>(budgets.Validate);

        Assert.Contains("budgets.session.max_cost", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ZeroLimits_AreLegal()
    {
        // "No calls at all" is a coherent configuration: a paused agent.
        new BudgetPolicy { Session = new BudgetLimits { MaxCalls = 0, MaxCost = 0 } }.Validate();
    }
}
