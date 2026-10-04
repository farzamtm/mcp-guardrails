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

        Assert.Equal(2, policy.EffectiveRules.Count);

        Assert.Equal("allow-reads", policy.EffectiveRules[0].Name);
        Assert.Equal(Verdict.Allow, policy.EffectiveRules[0].EffectiveDecision);
        Assert.Equal("fs__read_file", policy.EffectiveRules[0].EffectiveMatch.Tool);

        Assert.Equal(Verdict.Deny, policy.EffectiveRules[1].EffectiveDecision);
        Assert.Equal("Writing is not permitted here.", policy.EffectiveRules[1].Message);
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

        Assert.Equal(Verdict.RequireApproval, Assert.Single(policy.EffectiveRules).EffectiveDecision);
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

        var rule = Assert.Single(policy.EffectiveRules);

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

        var rule = Assert.Single(policy.EffectiveRules);

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
        Assert.Empty(PolicyLoader.Parse(yaml).EffectiveRules);
    }

    [Fact]
    public void LoadFromFileOrEmpty_ReturnsEmptyWhenNoFileExists()
    {
        // The adoption default: no policy file means pure passthrough.
        var missing = Path.Combine(_directory, "does-not-exist.yaml");

        Assert.Empty(PolicyLoader.LoadFromFileOrEmpty(missing).EffectiveRules);
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

        Assert.Equal("deny-writes", Assert.Single(PolicyLoader.LoadFromFileOrEmpty(path).EffectiveRules).Name);
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
        // "true" quoted is the string true, not the boolean. Annotation matching
        // compares real booleans, so the distinction has to survive the
        // conversion or `destructiveHint: "true"` would bind to nothing.
        var policy = PolicyLoader.Parse("""
            rules:
              - name: "true"
                match:
                  tool: "123"
            """);

        var rule = Assert.Single(policy.EffectiveRules);
        Assert.Equal("true", rule.Name);
        Assert.Equal("123", rule.EffectiveMatch.Tool);
    }

    // ------------------------------------------------------ the richer matchers

    [Fact]
    public void Parse_ReadsAnnotationMatches()
    {
        var policy = PolicyLoader.Parse("""
            rules:
              - name: approve-destructive
                match:
                  annotations:
                    destructiveHint: true
                    readOnlyHint: false
                decision: require_approval
            """);

        var annotations = Assert.Single(policy.EffectiveRules).EffectiveMatch.Annotations;

        Assert.NotNull(annotations);
        Assert.True(annotations.DestructiveHint);
        Assert.False(annotations.ReadOnlyHint);
        Assert.Null(annotations.IdempotentHint);
    }

    [Fact]
    public void Parse_ReadsArgumentPredicates()
    {
        var policy = PolicyLoader.Parse("""
            rules:
              - name: cap-exports
                match:
                  tool: ct__export_*
                  args:
                    - path: $.limit
                      gt: 100
                    - path: $.format
                      in: [csv, json]
                decision: deny
            """);

        var arguments = Assert.Single(policy.EffectiveRules).EffectiveMatch.Arguments;

        Assert.NotNull(arguments);
        Assert.Equal(2, arguments.Count);
        Assert.Equal("$.limit", arguments[0].Path);
        Assert.Equal(100, arguments[0].Gt);
        Assert.Equal(2, arguments[1].In?.Count);
    }

    [Fact]
    public void Parse_RejectsAnEmptyAnnotationsBlock()
    {
        var exception = Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            rules:
              - name: pointless
                match:
                  annotations: {}
                decision: deny
            """));

        Assert.Contains("empty 'annotations'", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_RejectsAnEmptyArgsList()
    {
        var exception = Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            rules:
              - name: pointless
                match:
                  args: []
                decision: deny
            """));

        Assert.Contains("empty 'args' list", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_RejectsAPredicateTheEvaluatorCouldNotHonour()
    {
        // Load-time validation is the point: an unsupported path would otherwise
        // produce a rule that never fires, and a guardrail that silently does
        // nothing is worse than one that refuses to start.
        var exception = Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            rules:
              - name: recursive-descent-is-not-supported
                match:
                  args:
                    - path: $..limit
                      gt: 100
                decision: deny
            """));

        Assert.Contains("unsupported argument path", exception.Message, StringComparison.Ordinal);
        Assert.Contains("recursive-descent-is-not-supported", exception.Message, StringComparison.Ordinal);
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

    [Fact]
    public void ALoadedGlobAnnotationAndArgumentRule_DecidesARealCall()
    {
        // One test that proves the whole chain: YAML text to JsonNode to typed
        // policy to a decision, with all three condition types in play.
        var policy = PolicyLoader.Parse("""
            rules:
              - name: sandbox-escape
                match:
                  tool: fs__*
                  annotations:
                    readOnlyHint: false
                  args:
                    - path: $.path
                      not_prefix: /workspace/
                decision: deny
                message: Write inside /workspace/ instead.
            """);

        var evaluator = new PolicyEvaluator(policy);

        var escaping = new ToolCallFacts(
            "fs__write_file",
            TestArguments.From("""{ "path": "/etc/passwd" }"""),
            new ToolAnnotationFacts(ReadOnlyHint: false));

        var inSandbox = new ToolCallFacts(
            "fs__write_file",
            TestArguments.From("""{ "path": "/workspace/notes.txt" }"""),
            new ToolAnnotationFacts(ReadOnlyHint: false));

        Assert.Equal(Verdict.Deny, evaluator.Evaluate(escaping).Verdict);
        Assert.Contains(
            "Write inside /workspace/ instead.",
            evaluator.Evaluate(escaping).ToModelMessage(),
            StringComparison.Ordinal);

        Assert.Equal(Verdict.Allow, evaluator.Evaluate(inSandbox).Verdict);
    }

    [Fact]
    public void Parse_ReadsAQuotedLeadingStarGlob()
    {
        // The cross-server form the README recommends. It only reaches the
        // matcher when quoted: YAML reads a bare leading '*' as an alias
        // indicator, so the unquoted spelling never becomes a glob at all.
        var policy = PolicyLoader.Parse("""
            rules:
              - name: no-deletes-anywhere
                match:
                  tool: "*__delete_*"
                decision: deny
            """);

        var evaluator = new PolicyEvaluator(policy);

        Assert.Equal(
            Verdict.Deny,
            evaluator.Evaluate(new ToolCallFacts("git__delete_branch")).Verdict);

        Assert.Equal(
            Verdict.Allow,
            evaluator.Evaluate(new ToolCallFacts("git__create_branch")).Verdict);
    }

    [Fact]
    public void Parse_RejectsAnUnquotedLeadingStarGlobAsYamlSyntax()
    {
        // Pinned so the failure stays a named configuration error rather than
        // something that silently changes meaning later.
        var exception = Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            rules:
              - name: no-deletes-anywhere
                match:
                  tool: *__delete_*
                decision: deny
            """));

        Assert.Contains("YAML syntax error", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_ReadsAServerCondition()
    {
        var policy = PolicyLoader.Parse("""
            rules:
              - name: approve-github-writes
                match:
                  server: github
                  annotations: { readOnlyHint: false }
                decision: require_approval
            """);

        Assert.Equal("github", Assert.Single(policy.EffectiveRules).EffectiveMatch.Server);
    }
}
