using McpGuardrails.Core.Budget;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Budget;

/// <summary>
/// The YAML surface of budgets: what an operator actually writes in a file.
/// </summary>
public sealed class BudgetPolicyLoadingTests
{
    [Fact]
    public void AFileWithNoBudgets_HasNone()
    {
        var document = PolicyLoader.Parse("""
            rules:
              - name: allow-all
                decision: allow
            """);

        Assert.Null(document.Budgets);
        Assert.True(document.EffectiveBudgets.IsEmpty);
    }

    [Fact]
    public void AFileWithBudgetsButNoRules_Loads()
    {
        // Regression. Budgets made "a policy file with no rules:" a normal thing
        // to write for the first time, and it crashed: property initializers are
        // not applied by the source-generated deserializer, so Rules came back
        // null and validation threw a NullReferenceException on the first
        // iteration. Same trap the Match and Decision properties already document.
        var document = PolicyLoader.Parse("""
            budgets:
              session:
                max_calls: 10
            """);

        Assert.Null(document.Rules);
        Assert.Empty(document.EffectiveRules);

        // And it behaves: no rules means no opinion, so calls are allowed and
        // only the budget constrains them.
        Assert.Equal(
            Verdict.Allow,
            new PolicyEvaluator(document).Evaluate(new ToolCallFacts("fs__read_file")).Verdict);
    }

    [Fact]
    public void SessionLimits_AreParsed()
    {
        var document = PolicyLoader.Parse("""
            budgets:
              session:
                max_calls: 200
                max_cost: 50
            """);

        Assert.Equal(200, document.EffectiveBudgets.Session?.MaxCalls);
        Assert.Equal(50, document.EffectiveBudgets.Session?.MaxCost);
    }

    [Fact]
    public void OneLimitWithoutTheOther_IsFine()
    {
        var document = PolicyLoader.Parse("""
            budgets:
              session:
                max_cost: 50
            """);

        Assert.Null(document.EffectiveBudgets.Session?.MaxCalls);
        Assert.Equal(50, document.EffectiveBudgets.Session?.MaxCost);
    }

    [Fact]
    public void DailyLimits_AreParsedAlongsideSessionLimits()
    {
        var document = PolicyLoader.Parse("""
            budgets:
              session:
                max_calls: 200
              daily:
                max_calls: 1000
                max_cost: 500
            """);

        Assert.Equal(200, document.EffectiveBudgets.Session?.MaxCalls);
        Assert.Equal(1000, document.EffectiveBudgets.Daily?.MaxCalls);
        Assert.Equal(500, document.EffectiveBudgets.Daily?.MaxCost);
    }

    [Fact]
    public void AnEmptyDailySection_FailsAtLoadTime()
    {
        // At load time, not on the first call: the operator finds out when they
        // start the proxy, not hours into a day that was never capped.
        var error = Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            budgets:
              daily: {}
            """));

        Assert.Contains("budgets.daily", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEmptyBudgetSection_FailsAtLoadTime()
    {
        var error = Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            budgets:
              session: {}
            """));

        Assert.Contains("sets no limits", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ANegativeLimit_FailsAtLoadTime()
    {
        var error = Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            budgets:
              session:
                max_calls: -1
            """));

        Assert.Contains("cannot be negative", error.Message, StringComparison.Ordinal);
    }

    // -------------------------------------------------------------- rule cost

    [Fact]
    public void ARuleWithoutACost_CostsOne()
    {
        var document = PolicyLoader.Parse("""
            rules:
              - name: allow-all
                decision: allow
            """);

        // Budgets are meaningful before anyone writes a single cost:.
        Assert.Null(document.EffectiveRules[0].Cost);
        Assert.Equal(1, document.EffectiveRules[0].EffectiveCost);
    }

    [Fact]
    public void ARuleCost_IsParsed()
    {
        var document = PolicyLoader.Parse("""
            rules:
              - name: expensive-export
                match:
                  tool: ct__export_*
                decision: allow
                cost: 25
            """);

        Assert.Equal(25, document.EffectiveRules[0].EffectiveCost);
    }

    [Fact]
    public void AZeroCost_MakesCallsFree()
    {
        var document = PolicyLoader.Parse("""
            rules:
              - name: reads-are-free
                match:
                  annotations:
                    readOnlyHint: true
                decision: allow
                cost: 0
            """);

        Assert.Equal(0, document.EffectiveRules[0].EffectiveCost);
    }

    [Fact]
    public void ANegativeCost_FailsAtLoadTime()
    {
        // A negative cost would refund budget, turning a cap into something an
        // agent can top up by calling the cheap tool in a loop.
        var error = Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            rules:
              - name: refund
                decision: allow
                cost: -5
            """));

        Assert.Contains("negative 'cost'", error.Message, StringComparison.Ordinal);
    }

    // ------------------------------------------------------- cost in practice

    [Fact]
    public void TheMatchedRulesCost_ReachesTheBudget()
    {
        // The whole path in one test: YAML -> rule -> decision -> charge.
        var document = PolicyLoader.Parse("""
            budgets:
              session:
                max_cost: 30
            rules:
              - name: expensive-export
                match:
                  tool: ct__export_all
                decision: allow
                cost: 25
              - name: everything-else
                decision: allow
            """);

        var evaluator = new PolicyEvaluator(document);
        var gate = new BudgetGate(new InMemoryBudgetStore(document.EffectiveBudgets.Session));

        var first = gate.Apply(evaluator.Evaluate(new ToolCallFacts("ct__export_all")));
        Assert.Equal(Verdict.Allow, first.Verdict);
        Assert.Equal(25, gate.Store.Cost);

        // 25 spent, 30 capped: a second export does not fit, but a default-priced
        // call still does.
        var second = gate.Apply(evaluator.Evaluate(new ToolCallFacts("ct__export_all")));
        Assert.Equal(Verdict.Deny, second.Verdict);
        Assert.Equal(DecisionSource.Budget, second.Source);

        var cheap = gate.Apply(evaluator.Evaluate(new ToolCallFacts("ct__read_one")));
        Assert.Equal(Verdict.Allow, cheap.Verdict);
        Assert.Equal(26, gate.Store.Cost);
    }

    [Fact]
    public void ACallNoRuleMatched_CostsTheDefault()
    {
        var gate = new BudgetGate(new InMemoryBudgetStore(new BudgetLimits { MaxCost = 2 }));

        gate.Apply(PolicyEvaluator.Empty.Evaluate(new ToolCallFacts("fs__read_file")));

        Assert.Equal(1, gate.Store.Cost);
    }
}
