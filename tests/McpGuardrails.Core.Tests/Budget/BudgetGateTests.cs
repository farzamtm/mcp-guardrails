using McpGuardrails.Core.Budget;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Budget;

public sealed class BudgetGateTests
{
    private static BudgetGate Gate(long? maxCalls = null, long? maxCost = null) =>
        new(new InMemoryBudgetStore(new BudgetLimits { MaxCalls = maxCalls, MaxCost = maxCost }));

    private static Decision Allowed(long cost = 1, IReadOnlyList<string>? trail = null) =>
        new(Verdict.Allow, "allowed by rule 'x'", "x", trail) { Cost = cost };

    // ------------------------------------------------------------ pass-through

    [Fact]
    public void ACallWithinBudget_KeepsThePolicyDecision()
    {
        var decision = Allowed();

        Assert.Same(decision, Gate(maxCalls: 2).Apply(decision));
    }

    [Fact]
    public void AnUnlimitedGate_NeverRefuses()
    {
        var gate = BudgetGate.Unlimited;

        for (var i = 0; i < 50; i++)
        {
            Assert.Equal(Verdict.Allow, gate.Apply(Allowed(1_000_000)).Verdict);
        }
    }

    // --------------------------------------------------------- what gets charged

    [Fact]
    public void ACallThePolicyAlreadyRefused_SpendsNothing()
    {
        var gate = Gate(maxCalls: 1);
        var denied = new Decision(Verdict.Deny, "no", "deny-writes");

        Assert.Same(denied, gate.Apply(denied));

        // The denied call never reached a server, so the one unit of budget is
        // still there for the call that does.
        Assert.Equal(0, gate.Store.Calls);
        Assert.Equal(Verdict.Allow, gate.Apply(Allowed()).Verdict);
    }

    [Fact]
    public void ACallAwaitingApproval_SpendsNothing()
    {
        // require_approval is blocked too: it has not been forwarded, and if a
        // human later refuses it, budget charged now could never be given back.
        var gate = Gate(maxCost: 10);

        gate.Apply(new Decision(Verdict.RequireApproval, "ask first", "approve-destructive"));

        Assert.Equal(0, gate.Store.Cost);
    }

    [Fact]
    public void TheRulesCost_IsWhatGetsCharged()
    {
        var gate = Gate(maxCost: 100);

        gate.Apply(Allowed(cost: 25));
        gate.Apply(Allowed(cost: 5));

        Assert.Equal(30, gate.Store.Cost);
        Assert.Equal(2, gate.Store.Calls);
    }

    [Fact]
    public void ACallToAnUnknownTool_SpendsNothing()
    {
        // Policy allowed it, but no downstream server owns the name, so the call
        // handler answers "unknown tool" and nothing is forwarded.
        var gate = Gate(maxCalls: 1);
        var allowed = Allowed(cost: 1);

        for (var i = 0; i < 5; i++)
        {
            Assert.Same(allowed, gate.Apply(allowed, toolResolved: false));
        }

        Assert.Equal((0, 0), (gate.Store.Calls, gate.Store.Cost));

        // The one unit is still there for a call that actually goes out.
        Assert.Same(allowed, gate.Apply(allowed, toolResolved: true));
        Assert.Equal(1, gate.Store.Calls);
    }

    [Fact]
    public void ACallToAnUnknownTool_IsNotRefusedByAnExhaustedBudget()
    {
        // Refusing it as "budget exhausted" would tell the model to stop working
        // over a call that costs nothing; the call handler's "unknown tool" is
        // the answer it needs.
        var gate = Gate(maxCalls: 0);
        var allowed = Allowed();

        Assert.Same(allowed, gate.Apply(allowed, toolResolved: false));
    }

    [Fact]
    public void ACallerThatDoesNotSayWhetherTheToolResolved_IsCharged()
    {
        // The default must be the bounded direction: forgetting the argument
        // costs budget rather than silently making calls free.
        var gate = Gate(maxCalls: 5);

        gate.Apply(Allowed());

        Assert.Equal(1, gate.Store.Calls);
    }

    // ------------------------------------------------------------- refusals

    [Fact]
    public void ExhaustingTheCostBudget_DeniesWithTheNumbers()
    {
        var gate = Gate(maxCost: 10);

        gate.Apply(Allowed(cost: 8));

        var refused = gate.Apply(Allowed(cost: 5));

        Assert.Equal(Verdict.Deny, refused.Verdict);
        Assert.True(refused.IsBlocked);
        Assert.Equal(DecisionSource.Budget, refused.Source);
        Assert.Equal("session.max_cost", refused.RuleName);

        // The numbers are in the message so a human reading the transcript can
        // tell whether the cap was too tight, without opening the audit log.
        Assert.Contains("costs 5", refused.Reason, StringComparison.Ordinal);
        Assert.Contains("spent 8", refused.Reason, StringComparison.Ordinal);
        Assert.Contains("10 budget", refused.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ExhaustingTheCallBudget_DeniesWithTheNumbers()
    {
        var gate = Gate(maxCalls: 2);

        gate.Apply(Allowed());
        gate.Apply(Allowed());

        var refused = gate.Apply(Allowed());

        Assert.Equal("session.max_calls", refused.RuleName);
        Assert.Contains("made 2 tool calls", refused.Reason, StringComparison.Ordinal);
        Assert.Contains("limit of 2", refused.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ABudgetDenial_TellsTheModelToStopRatherThanRetry()
    {
        // The difference from a policy denial. "Choose a different approach" is
        // right when one tool is forbidden and wrong when the session is out of
        // money - there, every approach fails, and an agent that keeps trying
        // just burns the user's time.
        var refused = Gate(maxCalls: 0).Apply(Allowed());

        Assert.Contains("Stop calling tools", refused.Reason, StringComparison.Ordinal);
        Assert.Contains("tell the user", refused.Reason, StringComparison.Ordinal);
        Assert.Contains("budgets.session.max_calls", refused.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ABudgetDenial_IsWordedAsABudgetNotAPolicyRule()
    {
        var message = Gate(maxCalls: 0).Apply(Allowed()).ToModelMessage();

        Assert.StartsWith(
            "Blocked by guardrails budget 'session.max_calls':",
            message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void ABudgetDenial_KeepsTheCostThatWasRefused()
    {
        var refused = Gate(maxCost: 1).Apply(Allowed(cost: 9));

        // Not charged, but recorded: the audit line then says what the call would
        // have cost, which is how you find the rule that needs repricing.
        Assert.Equal(9, refused.Cost);
    }

    // ---------------------------------------------------------------- trail

    [Fact]
    public void WithoutExplain_TheRefusalHasNoTrail()
    {
        Assert.Null(Gate(maxCalls: 0).Apply(Allowed()).Trail);
    }

    [Fact]
    public void WithExplain_TheRefusalIsAppendedToThePolicyTrail()
    {
        var refused = Gate(maxCalls: 0)
            .Apply(Allowed(trail: ["rule 'allow-reads': MATCHED -> allow"]));

        Assert.Equal(
            ["rule 'allow-reads': MATCHED -> allow", "budget 'session': exhausted -> deny"],
            refused.Trail);
    }

    // ----------------------------------------------------------------- scope

    [Fact]
    public void TheScopeName_AppearsInTheRefusal()
    {
        var gate = new BudgetGate(
            new InMemoryBudgetStore(new BudgetLimits { MaxCalls = 0 }),
            "weekly");

        var refused = gate.Apply(Allowed());

        Assert.Equal("weekly.max_calls", refused.RuleName);
        Assert.Contains("the weekly has made", refused.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ADailyCallRefusal_SaysWhenItResetsInsteadOfNewSession()
    {
        // "Start a new session" is exactly the advice that does not help against
        // a daily cap, and the model would follow it.
        var refused = new BudgetGate(
            new InMemoryBudgetStore(new BudgetLimits { MaxCalls = 3 }),
            BudgetGate.DailyScope);

        refused.Apply(Allowed());
        refused.Apply(Allowed());
        refused.Apply(Allowed());

        var denial = refused.Apply(Allowed());

        Assert.Equal("daily.max_calls", denial.RuleName);
        Assert.Contains("3 tool calls have been made today (UTC)", denial.Reason, StringComparison.Ordinal);
        Assert.Contains("daily limit of 3", denial.Reason, StringComparison.Ordinal);
        Assert.Contains("budgets.daily.max_calls", denial.Reason, StringComparison.Ordinal);
        Assert.Contains("resets at 00:00 UTC", denial.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain("new session", denial.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ADailyCostRefusal_GivesTheNumbersAndTheReset()
    {
        var gate = new BudgetGate(
            new InMemoryBudgetStore(new BudgetLimits { MaxCost = 50 }),
            BudgetGate.DailyScope);

        gate.Apply(Allowed(cost: 40));

        var denial = gate.Apply(Allowed(cost: 25));

        Assert.Equal("daily.max_cost", denial.RuleName);
        Assert.Contains("costs 25", denial.Reason, StringComparison.Ordinal);
        Assert.Contains("40 of today's 50 budget", denial.Reason, StringComparison.Ordinal);
        Assert.Contains("budgets.daily.max_cost", denial.Reason, StringComparison.Ordinal);
        Assert.Contains("resets at 00:00 UTC", denial.Reason, StringComparison.Ordinal);
    }

    // ------------------------------------------------------- session + daily

    private static (BudgetGate Gate, InMemoryBudgetStore Session, InMemoryBudgetStore Daily) Both(
        BudgetLimits session,
        BudgetLimits daily)
    {
        var sessionStore = new InMemoryBudgetStore(session);
        var dailyStore = new InMemoryBudgetStore(daily);

        return (new BudgetGate(sessionStore, dailyStore), sessionStore, dailyStore);
    }

    [Fact]
    public void WithBothScopes_ACallWithinBoth_IsChargedToBoth()
    {
        var (gate, session, daily) = Both(new BudgetLimits { MaxCalls = 5 }, new BudgetLimits { MaxCalls = 5 });

        var decision = Allowed(cost: 3);

        Assert.Same(decision, gate.Apply(decision));
        Assert.Equal((1, 3), (session.Calls, session.Cost));
        Assert.Equal((1, 3), (daily.Calls, daily.Cost));
        Assert.Same(session, gate.Store);
        Assert.Same(daily, gate.DailyStore);
    }

    [Fact]
    public void WithBothScopes_ACallToAnUnknownTool_IsChargedToNeither()
    {
        var (gate, session, daily) = Both(new BudgetLimits { MaxCalls = 5 }, new BudgetLimits { MaxCalls = 5 });

        var decision = Allowed(cost: 3);

        Assert.Same(decision, gate.Apply(decision, toolResolved: false));
        Assert.Equal((0, 0), (session.Calls, session.Cost));
        Assert.Equal((0, 0), (daily.Calls, daily.Cost));
    }

    [Fact]
    public void WithBothScopes_TheSessionRefusal_LeavesTheDayUntouched()
    {
        var (gate, _, daily) = Both(new BudgetLimits { MaxCalls = 0 }, new BudgetLimits { MaxCalls = 5 });

        var refused = gate.Apply(Allowed());

        Assert.Equal("session.max_calls", refused.RuleName);

        // The session said no first, so the shared daily budget never saw it.
        Assert.Equal(0, daily.Calls);
    }

    [Fact]
    public void WithBothScopes_TheDailyRefusal_HandsTheSessionChargeBack()
    {
        var (gate, session, _) = Both(new BudgetLimits { MaxCost = 100 }, new BudgetLimits { MaxCost = 4 });

        Assert.Equal(Verdict.Allow, gate.Apply(Allowed(cost: 3)).Verdict);

        var refused = gate.Apply(Allowed(cost: 3));

        Assert.Equal("daily.max_cost", refused.RuleName);

        // The refused call was not forwarded, so the session paid only for the
        // first one - otherwise a daily refusal would quietly eat session budget.
        Assert.Equal((1, 3), (session.Calls, session.Cost));
    }

    [Fact]
    public void WithBothScopes_AFailingDailyStore_FailsTheCallAndRefundsTheSession()
    {
        var session = new InMemoryBudgetStore(new BudgetLimits { MaxCalls = 5 });
        var gate = new BudgetGate(session, new ThrowingStore());

        // Fails closed: the exception propagates, so the call is not forwarded.
        Assert.Throws<InvalidOperationException>(() => gate.Apply(Allowed(cost: 2)));

        Assert.Equal((0, 0), (session.Calls, session.Cost));
    }

    [Fact]
    public void WithBothScopes_ConcurrentCalls_OvershootNeither()
    {
        var (gate, session, daily) = Both(new BudgetLimits { MaxCalls = 30 }, new BudgetLimits { MaxCalls = 10 });
        var allowed = 0;

        Parallel.For(0, 64, _ =>
        {
            if (!gate.Apply(Allowed()).IsBlocked)
            {
                Interlocked.Increment(ref allowed);
            }
        });

        Assert.Equal(10, allowed);
        Assert.Equal(10, daily.Calls);

        // Every daily refusal was refunded, so the session counts only the
        // calls that actually went out.
        Assert.Equal(10, session.Calls);
    }

    private sealed class ThrowingStore : IBudgetStore
    {
        public long Calls => 0;

        public long Cost => 0;

        public BudgetCharge TryCharge(long cost) => throw new InvalidOperationException("disk on fire");
    }

    // ------------------------------------------------------------ composition

    [Fact]
    public void For_NoBudgets_IsTheUnlimitedGateAndOpensNothing()
    {
        var gate = BudgetGate.For(BudgetPolicy.None, _ => throw new InvalidOperationException("opened"));

        Assert.Same(BudgetGate.Unlimited, gate);
    }

    [Fact]
    public void For_SessionOnly_NeverOpensTheDailyStore()
    {
        var gate = BudgetGate.For(
            new BudgetPolicy { Session = new BudgetLimits { MaxCalls = 0 } },
            _ => throw new InvalidOperationException("opened"));

        Assert.Null(gate.DailyStore);
        Assert.Equal("session.max_calls", gate.Apply(Allowed()).RuleName);
    }

    [Fact]
    public void For_DailyOnly_EnforcesTheDailyScope()
    {
        BudgetLimits? opened = null;
        var limits = new BudgetLimits { MaxCalls = 0 };

        var gate = BudgetGate.For(
            new BudgetPolicy { Daily = limits },
            l => new InMemoryBudgetStore(opened = l));

        Assert.Same(limits, opened);
        Assert.Equal("daily.max_calls", gate.Apply(Allowed()).RuleName);
    }

    [Fact]
    public void For_Both_EnforcesBoth()
    {
        var gate = BudgetGate.For(
            new BudgetPolicy
            {
                Session = new BudgetLimits { MaxCalls = 5 },
                Daily = new BudgetLimits { MaxCalls = 1 },
            },
            l => new InMemoryBudgetStore(l));

        Assert.NotNull(gate.DailyStore);
        Assert.Equal(Verdict.Allow, gate.Apply(Allowed()).Verdict);
        Assert.Equal("daily.max_calls", gate.Apply(Allowed()).RuleName);
    }

    [Fact]
    public void For_RejectsNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => BudgetGate.For(null!, l => new InMemoryBudgetStore(l)));
        Assert.Throws<ArgumentNullException>(() => BudgetGate.For(BudgetPolicy.None, null!));
    }

    [Fact]
    public void TheTwoScopeGate_RejectsANullDailyStore()
    {
        Assert.Throws<ArgumentNullException>(() => new BudgetGate(new InMemoryBudgetStore(), (IBudgetStore)null!));
    }

    // ------------------------------------------------------------- arguments

    [Fact]
    public void TheGate_RejectsANullStore()
    {
        Assert.Throws<ArgumentNullException>(() => new BudgetGate(null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void TheGate_RejectsABlankScope(string scope)
    {
        Assert.Throws<ArgumentException>(() => new BudgetGate(new InMemoryBudgetStore(), scope));
    }

    [Fact]
    public void TheGate_RejectsANullDecision()
    {
        Assert.Throws<ArgumentNullException>(() => Gate().Apply(null!));
    }
}
