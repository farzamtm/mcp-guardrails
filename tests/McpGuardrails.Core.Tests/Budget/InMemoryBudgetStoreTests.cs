using McpGuardrails.Core.Budget;

namespace McpGuardrails.Core.Tests.Budget;

public sealed class InMemoryBudgetStoreTests
{
    private static InMemoryBudgetStore Store(long? maxCalls = null, long? maxCost = null) =>
        new(new BudgetLimits { MaxCalls = maxCalls, MaxCost = maxCost });

    // ------------------------------------------------------------- no limits

    [Fact]
    public void WithoutLimits_ChargesForeverAndStillCounts()
    {
        var store = new InMemoryBudgetStore();

        for (var i = 0; i < 100; i++)
        {
            Assert.True(store.TryCharge(7).Allowed);
        }

        // Counting without capping is the passthrough default: an operator who
        // has written no budget can still read what a session spent.
        Assert.Equal(100, store.Calls);
        Assert.Equal(700, store.Cost);
    }

    [Fact]
    public void NullLimits_AreTheSameAsNoLimits()
    {
        var store = new InMemoryBudgetStore(new BudgetLimits());

        Assert.True(store.TryCharge(long.MaxValue).Allowed);
        Assert.True(store.TryCharge(1).Allowed);
    }

    // ---------------------------------------------------------- the call cap

    [Fact]
    public void CallCap_AllowsExactlyThatManyCalls()
    {
        var store = Store(maxCalls: 3);

        Assert.True(store.TryCharge(0).Allowed);
        Assert.True(store.TryCharge(0).Allowed);
        Assert.True(store.TryCharge(0).Allowed);

        var refused = store.TryCharge(0);

        Assert.False(refused.Allowed);
        Assert.Equal(BudgetDimension.Calls, refused.Exceeded);
        Assert.Equal(3, refused.Used);
        Assert.Equal(3, refused.Cap);
        Assert.Equal(1, refused.Requested);
    }

    [Fact]
    public void ZeroCostCalls_StillCountAgainstTheCallCap()
    {
        // The reason both dimensions exist: cost: 0 makes a call free to spend,
        // not free to make. Otherwise a free tool is an unbounded loop.
        var store = Store(maxCalls: 1, maxCost: 100);

        Assert.True(store.TryCharge(0).Allowed);
        Assert.False(store.TryCharge(0).Allowed);
    }

    [Fact]
    public void ZeroCallCap_RefusesTheFirstCall()
    {
        // A coherent thing to configure: a paused agent.
        Assert.False(Store(maxCalls: 0).TryCharge(0).Allowed);
    }

    // ---------------------------------------------------------- the cost cap

    [Fact]
    public void CostCap_RefusesTheCallThatWouldExceedIt()
    {
        var store = Store(maxCost: 10);

        Assert.True(store.TryCharge(6).Allowed);

        var refused = store.TryCharge(5);

        Assert.False(refused.Allowed);
        Assert.Equal(BudgetDimension.Cost, refused.Exceeded);
        Assert.Equal(5, refused.Requested);
        Assert.Equal(6, refused.Used);
        Assert.Equal(10, refused.Cap);
    }

    [Fact]
    public void ARefusedCall_SpendsNothing()
    {
        var store = Store(maxCost: 10);

        store.TryCharge(9);
        store.TryCharge(5);   // refused

        // The refused call never reached a downstream server, so it must not have
        // consumed budget - otherwise a hard cap could be drained by calls that
        // did no work at all.
        Assert.Equal(9, store.Cost);
        Assert.Equal(1, store.Calls);

        // And the budget it did not spend is still spendable.
        Assert.True(store.TryCharge(1).Allowed);
    }

    [Fact]
    public void SpendingExactlyToTheCap_IsAllowed()
    {
        var store = Store(maxCost: 10);

        Assert.True(store.TryCharge(10).Allowed);
        Assert.False(store.TryCharge(1).Allowed);
    }

    [Fact]
    public void ACallCostingMoreThanTheWholeCap_IsRefusedImmediately()
    {
        var refused = Store(maxCost: 10).TryCharge(11);

        Assert.False(refused.Allowed);
        Assert.Equal(BudgetDimension.Cost, refused.Exceeded);
        Assert.Equal(0, refused.Used);
    }

    // ------------------------------------------------------------- overflow

    [Fact]
    public void ACostNearLongMaxValue_DoesNotWrapPastTheCap()
    {
        // The bug this guards against: used + cost overflowing to a negative
        // number, which compares as comfortably under the cap and hands out
        // unlimited budget precisely when the numbers are absurd.
        var store = Store(maxCost: long.MaxValue);

        Assert.True(store.TryCharge(long.MaxValue - 1).Allowed);

        var refused = store.TryCharge(2);

        Assert.False(refused.Allowed);
        Assert.Equal(BudgetDimension.Cost, refused.Exceeded);
        Assert.Equal(long.MaxValue - 1, store.Cost);
    }

    [Fact]
    public void UncappedTotals_SaturateInsteadOfWrapping()
    {
        var store = new InMemoryBudgetStore();

        Assert.True(store.TryCharge(long.MaxValue).Allowed);
        Assert.True(store.TryCharge(long.MaxValue).Allowed);

        // A statistic, not a limit - but a monotonic one. Wrapping would report a
        // session that spent more than any other as having spent nothing.
        Assert.Equal(long.MaxValue, store.Cost);
    }

    // ------------------------------------------------------------- arguments

    [Fact]
    public void ANegativeCost_IsRejectedRatherThanRefundingBudget()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Store(maxCost: 10).TryCharge(-1));
    }

    // ----------------------------------------------------------- concurrency

    [Fact]
    public void ConcurrentCalls_CannotOvershootTheCap()
    {
        // Nothing serialises tool calls, so this is the real shape of the risk: a
        // budget that can be overshot by racing is not a budget. 64 threads race
        // for 10 units; exactly 10 must get through.
        var store = Store(maxCost: 10);
        var allowed = 0;

        Parallel.For(0, 64, _ =>
        {
            if (store.TryCharge(1).Allowed)
            {
                Interlocked.Increment(ref allowed);
            }
        });

        Assert.Equal(10, allowed);
        Assert.Equal(10, store.Cost);
        Assert.Equal(10, store.Calls);
    }
}
