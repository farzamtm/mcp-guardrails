using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Policy;

public sealed class PolicyLoaderTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), $"guardrails-policy-{Guid.NewGuid():N}");

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private string WriteFile(string yaml)
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "policy.yaml");
        File.WriteAllText(path, yaml);
        return path;
    }

    // -------------------------------------------------------------- happy path

    [Fact]
    public void Parse_ReadsRulesInOrder()
    {
        var policy = PolicyLoader.Parse("""
            rules:
              - name: allow-reads
                match:
                  tool: fs__read_file
                decision: allow
              - name: deny-writes
                match:
                  tool: fs__write_file
                decision: deny
                message: Writing is not permitted here.
            """);

        Assert.Equal(2, policy.Rules.Count);

        Assert.Equal("allow-reads", policy.Rules[0].Name);
        Assert.Equal(Verdict.Allow, policy.Rules[0].EffectiveDecision);
        Assert.Equal("fs__read_file", policy.Rules[0].EffectiveMatch.Tool);

        Assert.Equal(Verdict.Deny, policy.Rules[1].EffectiveDecision);
        Assert.Equal("Writing is not permitted here.", policy.Rules[1].Message);
    }

    [Fact]
    public void Parse_ReadsTheSnakeCasedApprovalVerdict()
    {
        // The wire spelling is require_approval, not RequireApproval; a mismatch
        // here would make every approval rule fail to load.
        var policy = PolicyLoader.Parse("""
            rules:
              - name: approve-deletes
                decision: require_approval
            """);

        Assert.Equal(Verdict.RequireApproval, Assert.Single(policy.Rules).EffectiveDecision);
    }

    [Fact]
    public void Parse_DefaultsDecisionToDeny()
    {
        // Omitting the decision must fail closed, not open. This is a regression
        // test: property initializers are ignored by source-generated
        // deserialization, so an omitted decision used to arrive as Verdict.Allow
        // (the enum's zero value) and a blocking rule would quietly permit.
        var policy = PolicyLoader.Parse("""
            rules:
              - name: no-decision-given
                match:
                  tool: fs__write_file
            """);

        var rule = Assert.Single(policy.Rules);

        Assert.Null(rule.Decision);                          // nothing was stated
        Assert.Equal(Verdict.Deny, rule.EffectiveDecision);  // and absent means deny
    }

    [Fact]
    public void Parse_AllowsARuleWithNoMatchConditions()
    {
        var policy = PolicyLoader.Parse("""
            rules:
              - name: catch-all
                decision: deny
            """);

        var rule = Assert.Single(policy.Rules);

        Assert.Null(rule.Match);                    // no conditions were given
        Assert.True(rule.EffectiveMatch.IsCatchAll); // so it applies to everything
    }

    // ------------------------------------------------------------ empty inputs

    [Theory]
    [InlineData("")]
    [InlineData("   \n  ")]
    [InlineData("# just a comment\n")]
    [InlineData("rules: []")]
    // A document that is literally null. Deserialization yields no object at
    // all, which is a different code path from "an object with no rules" and
    // must still land on the empty policy rather than a null reference.
    [InlineData("~")]
    [InlineData("null")]
    public void Parse_TreatsEmptyDocumentsAsNoRules(string yaml)
    {
        Assert.Empty(PolicyLoader.Parse(yaml).Rules);
    }

    [Fact]
    public void LoadFromFileOrEmpty_ReturnsEmptyWhenNoFileExists()
    {
        // The adoption default: no policy file means pure passthrough.
        var missing = Path.Combine(_directory, "does-not-exist.yaml");

        Assert.Empty(PolicyLoader.LoadFromFileOrEmpty(missing).Rules);
    }

    [Fact]
    public void LoadFromFileOrEmpty_ReadsFromDisk()
    {
        var path = WriteFile("""
            rules:
              - name: deny-writes
                match:
                  tool: fs__write_file
            """);

        Assert.Equal("deny-writes", Assert.Single(PolicyLoader.LoadFromFileOrEmpty(path).Rules).Name);
    }

    // -------------------------------------------------------------- bad inputs

    [Fact]
    public void Parse_ReportsYamlSyntaxErrorsWithPosition()
    {
        // Malformed policy must be fatal. Failing open on an unparseable security
        // policy is the worst available behaviour.
        var exception = Assert.Throws<PolicyException>(
            () => PolicyLoader.Parse("rules:\n  - name: broken\n   bad indent: ["));

        Assert.Contains("line", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_RejectsARuleWithoutAName()
    {
        var exception = Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            rules:
              - match:
                  tool: fs__write_file
                decision: deny
            """));

        Assert.Contains("name", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_RejectsAnUnknownDecision()
    {
        Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            rules:
              - name: typo
                decision: dney
            """));
    }

    [Fact]
    public void Parse_RejectsNull() =>
        Assert.Throws<ArgumentNullException>(() => PolicyLoader.Parse(null!));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void LoadFromFileOrEmpty_RejectsBlankPaths(string path) =>
        Assert.Throws<ArgumentException>(() => PolicyLoader.LoadFromFileOrEmpty(path));

    // ------------------------------------------------------------ scalar typing

    [Fact]
    public void Parse_PreservesQuotedStringsAsStrings()
    {
        // "true" quoted is the string true, not the boolean. Step 6 matches on
        // real booleans, so the distinction has to survive the conversion.
        var policy = PolicyLoader.Parse("""
            rules:
              - name: "true"
                match:
                  tool: "123"
            """);

        var rule = Assert.Single(policy.Rules);
        Assert.Equal("true", rule.Name);
        Assert.Equal("123", rule.EffectiveMatch.Tool);
    }

    // ------------------------------------------------------- end-to-end wiring

    [Fact]
    public void LoadedPolicy_ActuallyDrivesTheEvaluator()
    {
        var policy = PolicyLoader.Parse("""
            rules:
              - name: deny-bulk-export
                match:
                  tool: ct__export_customers
                decision: deny
                message: Exports over 100 rows need approval; try limit=100.
            """);

        var decision = new PolicyEvaluator(policy)
            .Evaluate(new ToolCallFacts("ct__export_customers"));

        Assert.Equal(Verdict.Deny, decision.Verdict);
        Assert.Contains("limit=100", decision.ToModelMessage(), StringComparison.Ordinal);
    }
}
