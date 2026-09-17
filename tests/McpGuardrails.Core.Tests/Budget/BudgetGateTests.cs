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
        // The parameter exists so the daily gate, when it lands, reads correctly
        // without touching any of this.
        var gate = new BudgetGate(
            new InMemoryBudgetStore(new BudgetLimits { MaxCalls = 0 }),
            "daily");

        var refused = gate.Apply(Allowed());

        Assert.Equal("daily.max_calls", refused.RuleName);
        Assert.Contains("the daily has made", refused.Reason, StringComparison.Ordinal);
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
