using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Policy;

public sealed class PolicyEvaluatorTests
{
    private static PolicyRule Rule(
        string name,
        string? tool = null,
        Verdict decision = Verdict.Deny,
        string? message = null) => new()
        {
            Name = name,
            Match = new PolicyMatch { Tool = tool },
            Decision = decision,
            Message = message,
        };

    private static PolicyEvaluator Evaluator(params PolicyRule[] rules) =>
        new(new PolicyDocument { Rules = rules });

    private static ToolCallFacts Call(string tool) => new(tool);

    // ---------------------------------------------------------------- defaults

    [Fact]
    public void EmptyPolicy_AllowsEverything()
    {
        // The adoption lever: an empty policy file is a pure passthrough.
        var decision = PolicyEvaluator.Empty.Evaluate(Call("fs__write_file"));

        Assert.Equal(Verdict.Allow, decision.Verdict);
        Assert.False(decision.IsBlocked);
        Assert.Null(decision.RuleName);
    }

    [Fact]
    public void NoRuleMatches_FallsBackToAllow()
    {
        var decision = Evaluator(Rule("deny-writes", tool: "fs__write_file"))
            .Evaluate(Call("fs__read_file"));

        Assert.Equal(Verdict.Allow, decision.Verdict);
    }

    // ------------------------------------------------------------------ denial

    [Fact]
    public void MatchingDenyRule_BlocksTheCall()
    {
        var decision = Evaluator(Rule("deny-writes", tool: "fs__write_file"))
            .Evaluate(Call("fs__write_file"));

        Assert.Equal(Verdict.Deny, decision.Verdict);
        Assert.True(decision.IsBlocked);
        Assert.Equal("deny-writes", decision.RuleName);
    }

    [Fact]
    public void ToolMatching_IsCaseSensitiveAndExact()
    {
        var evaluator = Evaluator(Rule("deny-writes", tool: "fs__write_file"));

        // MCP tool names are case-sensitive identifiers; a near miss must not
        // silently match, or a rule would block more than it says.
        Assert.Equal(Verdict.Allow, evaluator.Evaluate(Call("fs__WRITE_FILE")).Verdict);
        Assert.Equal(Verdict.Allow, evaluator.Evaluate(Call("fs__write_file_2")).Verdict);
        Assert.Equal(Verdict.Deny, evaluator.Evaluate(Call("fs__write_file")).Verdict);
    }

    // -------------------------------------------------------- first match wins

    [Fact]
    public void FirstMatchingRuleWins_EvenIfALaterRuleAlsoMatches()
    {
        var decision = Evaluator(
                Rule("allow-first", tool: "fs__write_file", decision: Verdict.Allow),
                Rule("deny-second", tool: "fs__write_file"))
            .Evaluate(Call("fs__write_file"));

        Assert.Equal(Verdict.Allow, decision.Verdict);
        Assert.Equal("allow-first", decision.RuleName);
    }

    [Fact]
    public void CatchAllRule_MatchesAnyTool()
    {
        var evaluator = Evaluator(
            Rule("allow-reads", tool: "fs__read_file", decision: Verdict.Allow),
            Rule("deny-the-rest"));

        Assert.Equal(Verdict.Allow, evaluator.Evaluate(Call("fs__read_file")).Verdict);
        Assert.Equal("deny-the-rest", evaluator.Evaluate(Call("fs__write_file")).RuleName);
    }

    // ---------------------------------------------------------------- messages

    [Fact]
    public void CustomMessage_IsUsedVerbatim()
    {
        var decision = Evaluator(Rule(
                "deny-bulk-export",
                tool: "ct__export_customers",
                message: "Exports over 100 rows need approval; try limit=100."))
            .Evaluate(Call("ct__export_customers"));

        Assert.Equal("Exports over 100 rows need approval; try limit=100.", decision.Reason);
    }

    [Fact]
    public void ToModelMessage_NamesTheRuleAndExplainsItself()
    {
        var decision = Evaluator(Rule(
                "deny-bulk-export",
                tool: "ct__export_customers",
                message: "Try limit=100 instead."))
            .Evaluate(Call("ct__export_customers"));

        var message = decision.ToModelMessage();

        // The agent must be able to act on this, not just be stopped by it.
        Assert.Contains("deny-bulk-export", message, StringComparison.Ordinal);
        Assert.Contains("Try limit=100 instead.", message, StringComparison.Ordinal);
    }

    [Fact]
    public void ToModelMessage_OmitsRuleNameForTheDefaultDecision()
    {
        Assert.Equal(
            "Blocked by guardrails policy: No policy rule matched; default is allow.",
            Decision.DefaultAllow.ToModelMessage());
    }

    [Theory]
    [InlineData(Verdict.Deny, "Do not retry")]
    [InlineData(Verdict.RequireApproval, "human approval")]
    [InlineData(Verdict.Allow, "Explicitly allowed")]
    public void DefaultMessage_IsWrittenForTheModel(Verdict verdict, string expectedFragment)
    {
        var decision = Evaluator(Rule("r", tool: "t", decision: verdict))
            .Evaluate(Call("t"));

        Assert.Contains(expectedFragment, decision.Reason, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------- the --explain trail

    [Fact]
    public void Explain_RecordsEveryRuleConsidered()
    {
        var decision = Evaluator(
                Rule("first", tool: "other__tool"),
                Rule("second", tool: "fs__write_file"),
                Rule("third", tool: "fs__write_file"))
            .Evaluate(Call("fs__write_file"), explain: true);

        Assert.NotNull(decision.Trail);
        Assert.Collection(decision.Trail,
            line => Assert.Contains("'first': no match", line, StringComparison.Ordinal),
            line => Assert.Contains("'second': MATCHED -> deny", line, StringComparison.Ordinal));

        // Evaluation stops at the first match, so 'third' is never considered.
        Assert.DoesNotContain(decision.Trail, l => l.Contains("third", StringComparison.Ordinal));
    }

    [Fact]
    public void Explain_RecordsTheDefaultWhenNothingMatches()
    {
        var decision = Evaluator(Rule("nope", tool: "other"))
            .Evaluate(Call("fs__read_file"), explain: true);

        Assert.NotNull(decision.Trail);
        Assert.Contains(decision.Trail, l => l.Contains("default allow", StringComparison.Ordinal));
    }

    [Fact]
    public void TrailIsNotBuiltUnlessExplainIsRequested()
    {
        // The hot path runs for every tool call; it must not allocate a trail.
        var decision = Evaluator(Rule("r", tool: "t")).Evaluate(Call("t"));

        Assert.Null(decision.Trail);
    }

    // -------------------------------------------------------------- validation

    [Fact]
    public void Constructor_RejectsRuleWithoutAName()
    {
        var policy = new PolicyDocument { Rules = [new PolicyRule { Name = "  " }] };

        var exception = Assert.Throws<PolicyException>(() => new PolicyEvaluator(policy));
        Assert.Contains("name", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Constructor_RejectsAnEmptyToolPattern()
    {
        // "" almost certainly means "I meant to write something"; matching every
        // tool silently would be a nasty surprise.
        var policy = new PolicyDocument
        {
            Rules = [new PolicyRule { Name = "r", Match = new PolicyMatch { Tool = "" } }],
        };

        var exception = Assert.Throws<PolicyException>(() => new PolicyEvaluator(policy));
        Assert.Contains("empty 'tool'", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Constructor_RejectsAnUnknownDecision()
    {
        var policy = new PolicyDocument
        {
            Rules = [new PolicyRule { Name = "r", Decision = (Verdict)99 }],
        };

        Assert.Throws<PolicyException>(() => new PolicyEvaluator(policy));
    }

    [Fact]
    public void RejectsNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => new PolicyEvaluator(null!));
        Assert.Throws<ArgumentNullException>(() => PolicyEvaluator.Empty.Evaluate(null!));
    }

    [Fact]
    public void CatchAllDetection_ReflectsWhetherConditionsWereSpecified()
    {
        Assert.True(new PolicyMatch().IsCatchAll);
        Assert.False(new PolicyMatch { Tool = "fs__read_file" }.IsCatchAll);
        Assert.False(new PolicyMatch { Server = "fs" }.IsCatchAll);
    }

    [Fact]
    public void Constructor_RejectsAnEmptyServerPattern()
    {
        var policy = new PolicyDocument
        {
            Rules = [new PolicyRule { Name = "r", Match = new PolicyMatch { Server = " " } }],
        };

        var exception = Assert.Throws<PolicyException>(() => new PolicyEvaluator(policy));
        Assert.Contains("empty 'server'", exception.Message, StringComparison.Ordinal);
    }
}
