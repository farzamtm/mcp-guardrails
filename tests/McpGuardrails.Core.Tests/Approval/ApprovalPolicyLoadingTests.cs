using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Budget;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Approval;

/// <summary>
/// The YAML surface of approval, and how it reaches the gate.
/// </summary>
public sealed class ApprovalPolicyLoadingTests
{
    [Fact]
    public void ABareRequireApprovalRule_NeedsNoApprovalBlock()
    {
        var document = PolicyLoader.Parse("""
            rules:
              - name: approve-destructive
                match:
                  annotations:
                    destructiveHint: true
                decision: require_approval
            """);

        Assert.Null(document.EffectiveRules[0].Approval);
    }

    [Fact]
    public void AnApprovalBlock_IsParsed()
    {
        var document = PolicyLoader.Parse("""
            rules:
              - name: approve-destructive
                decision: require_approval
                approval:
                  mode: in_band
                  timeout_s: 45
                  on_timeout: allow
                  prompt: Delete the production bucket?
            """);

        var approval = document.EffectiveRules[0].Approval;

        Assert.Equal(ApprovalMode.InBand, approval?.EffectiveMode);
        Assert.Equal(TimeSpan.FromSeconds(45), approval?.EffectiveTimeout);
        Assert.Equal(Verdict.Allow, approval?.EffectiveOnTimeout);
        Assert.Equal("Delete the production bucket?", approval?.Prompt);
    }

    [Fact]
    public void AnApprovalBlockOnAnAllowRule_FailsAtLoadTime()
    {
        // It reads like a gate and is not one. One startup error beats a
        // destructive call the operator believed was being reviewed.
        var error = Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            rules:
              - name: not-really-gated
                decision: allow
                approval:
                  timeout_s: 30
            """));

        Assert.Contains("nobody would ever be asked", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ASlackApprover_FailsAtLoadTime()
    {
        var error = Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            rules:
              - name: approve-destructive
                decision: require_approval
                approval:
                  mode: slack
            """));

        Assert.Contains("not implemented yet", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnparseableTimeout_FailsAtLoadTime()
    {
        var error = Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            rules:
              - name: approve-destructive
                decision: require_approval
                approval:
                  timeout_s: 0
            """));

        Assert.Contains("timeout_s", error.Message, StringComparison.Ordinal);
    }

    // --------------------------------------------------- the whole path

    /// <summary>A channel that always says yes, and counts how often it was asked.</summary>
    private sealed class AlwaysApproves : IApprovalChannel
    {
        public int Asked { get; private set; }

        public ValueTask<ApprovalOutcome> RequestAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken)
        {
            Asked++;
            return ValueTask.FromResult(ApprovalOutcome.Approved);
        }
    }

    [Fact]
    public async Task ApprovalRunsBeforeTheBudget_SoOnlyApprovedCallsAreCharged()
    {
        // The ordering that matters: a call waiting on a human has not been
        // forwarded and must not spend anything, but once approved it is an
        // ordinary call and is charged like one.
        var document = PolicyLoader.Parse("""
            budgets:
              session:
                max_cost: 10
            rules:
              - name: approve-writes
                match:
                  tool: fs__write_*
                decision: require_approval
                cost: 4
              - name: allow-the-rest
                decision: allow
                cost: 0
            """);

        var evaluator = new PolicyEvaluator(document);
        var channel = new AlwaysApproves();
        var budget = new BudgetGate(new InMemoryBudgetStore(document.EffectiveBudgets.Session));

        var facts = new ToolCallFacts("fs__write_file");

        var approved = await ApprovalGate.ApplyAsync(evaluator.Evaluate(facts), facts, channel);
        var charged = budget.Apply(approved);

        Assert.Equal(1, channel.Asked);
        Assert.Equal(Verdict.Allow, charged.Verdict);
        Assert.Equal(ApprovalOutcome.Approved, charged.ApprovalResult);
        Assert.Equal(4, budget.Store.Cost);
    }

    [Fact]
    public async Task ADeclinedCall_CostsNothing()
    {
        var document = PolicyLoader.Parse("""
            budgets:
              session:
                max_cost: 10
            rules:
              - name: approve-writes
                match:
                  tool: fs__write_*
                decision: require_approval
                cost: 4
            """);

        var evaluator = new PolicyEvaluator(document);
        var budget = new BudgetGate(new InMemoryBudgetStore(document.EffectiveBudgets.Session));
        var facts = new ToolCallFacts("fs__write_file");

        var refused = await ApprovalGate.ApplyAsync(
            evaluator.Evaluate(facts),
            facts,
            new NeverApproves());

        budget.Apply(refused);

        Assert.Equal(Verdict.Deny, refused.Verdict);
        Assert.Equal(0, budget.Store.Cost);
    }

    private sealed class NeverApproves : IApprovalChannel
    {
        public ValueTask<ApprovalOutcome> RequestAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(ApprovalOutcome.Declined);
    }
}
