using System.Text.Json;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Policy;

/// <summary>
/// The three condition types, exercised through the evaluator rather than
/// against <c>RuleMatcher</c> directly: what matters is the decision a policy
/// file produces, and testing through the public surface keeps these tests
/// useful if the matcher is refactored.
/// </summary>
public sealed class RuleMatchingTests
{
    private static PolicyEvaluator Evaluator(params PolicyRule[] rules) =>
        new(new PolicyDocument { Rules = rules });

    private static PolicyRule Deny(string name, PolicyMatch match) =>
        new() { Name = name, Match = match, Decision = Verdict.Deny };

    // ------------------------------------------------------------------- globs

    [Fact]
    public void AGlobCoversAWholeServer()
    {
        var evaluator = Evaluator(Deny("no-git", new PolicyMatch { Tool = "git__*" }));

        Assert.Equal(Verdict.Deny, evaluator.Evaluate(new ToolCallFacts("git__push")).Verdict);
        Assert.Equal(Verdict.Allow, evaluator.Evaluate(new ToolCallFacts("fs__read_file")).Verdict);
    }

    [Fact]
    public void AGlobCanCoverAVerbAcrossServers()
    {
        // The case name-based rules cannot express: a server added next month
        // whose delete tool nobody has enumerated yet.
        var evaluator = Evaluator(Deny("no-deletes", new PolicyMatch { Tool = "*__delete_*" }));

        Assert.Equal(Verdict.Deny, evaluator.Evaluate(new ToolCallFacts("gh__delete_repo")).Verdict);
        Assert.Equal(Verdict.Deny, evaluator.Evaluate(new ToolCallFacts("fs__delete_file")).Verdict);
        Assert.Equal(Verdict.Allow, evaluator.Evaluate(new ToolCallFacts("fs__read_file")).Verdict);
    }

    // ------------------------------------------------------------- annotations

    [Fact]
    public void AnnotationsMatchOnWhatTheToolClaimsToDo()
    {
        var evaluator = Evaluator(Deny(
            "no-destructive",
            new PolicyMatch { Annotations = new AnnotationMatch { DestructiveHint = true } }));

        var destructive = new ToolCallFacts(
            "fs__delete_file",
            Annotations: new ToolAnnotationFacts(DestructiveHint: true));

        var readOnly = new ToolCallFacts(
            "fs__read_file",
            Annotations: new ToolAnnotationFacts(ReadOnlyHint: true));

        Assert.Equal(Verdict.Deny, evaluator.Evaluate(destructive).Verdict);
        Assert.Equal(Verdict.Allow, evaluator.Evaluate(readOnly).Verdict);
    }

    [Fact]
    public void AToolWithNoAnnotationsAtAll_StillCountsAsDestructive()
    {
        // A tool that says nothing about itself gets the specification's
        // defaults, so the blanket rule covers it. That is the whole point of
        // matching on annotations rather than on names.
        var evaluator = Evaluator(Deny(
            "no-destructive",
            new PolicyMatch { Annotations = new AnnotationMatch { DestructiveHint = true } }));

        Assert.Equal(Verdict.Deny, evaluator.Evaluate(new ToolCallFacts("weird__tool")).Verdict);
    }

    // --------------------------------------------------------------- arguments

    [Fact]
    public void AnArgumentPredicateNarrowsARuleToCertainCalls()
    {
        var evaluator = Evaluator(Deny(
            "cap-exports",
            new PolicyMatch
            {
                Tool = "ct__export_*",
                Arguments = [new ArgumentPredicate { Path = "$.limit", Gt = 100 }],
            }));

        var big = new ToolCallFacts(
            "ct__export_customers",
            TestArguments.From("""{ "limit": 5000 }"""));

        var small = new ToolCallFacts(
            "ct__export_customers",
            TestArguments.From("""{ "limit": 50 }"""));

        Assert.Equal(Verdict.Deny, evaluator.Evaluate(big).Verdict);
        Assert.Equal(Verdict.Allow, evaluator.Evaluate(small).Verdict);
    }

    [Fact]
    public void SeveralPredicatesMustAllHold()
    {
        var evaluator = Evaluator(Deny(
            "sandbox-escape",
            new PolicyMatch
            {
                Tool = "fs__write_file",
                Arguments =
                [
                    new ArgumentPredicate { Path = "$.path", NotPrefix = "/workspace/" },
                    new ArgumentPredicate
                    {
                        Path = "$.dry_run",
                        Eq = JsonDocument.Parse("false").RootElement.Clone(),
                    },
                ],
            }));

        var escaping = new ToolCallFacts(
            "fs__write_file",
            TestArguments.From("""{ "path": "/etc/passwd", "dry_run": false }"""));

        var inSandbox = new ToolCallFacts(
            "fs__write_file",
            TestArguments.From("""{ "path": "/workspace/notes.txt", "dry_run": false }"""));

        var rehearsal = new ToolCallFacts(
            "fs__write_file",
            TestArguments.From("""{ "path": "/etc/passwd", "dry_run": true }"""));

        Assert.Equal(Verdict.Deny, evaluator.Evaluate(escaping).Verdict);
        Assert.Equal(Verdict.Allow, evaluator.Evaluate(inSandbox).Verdict);
        Assert.Equal(Verdict.Allow, evaluator.Evaluate(rehearsal).Verdict);
    }

    // ------------------------------------------------------------- combination

    [Fact]
    public void TheThreeConditionTypesCombineWithAnd()
    {
        var evaluator = Evaluator(Deny(
            "narrow",
            new PolicyMatch
            {
                Tool = "fs__*",
                Annotations = new AnnotationMatch { ReadOnlyHint = false },
                Arguments = [new ArgumentPredicate { Path = "$.path", Prefix = "/etc/" }],
            }));

        var writable = new ToolAnnotationFacts(ReadOnlyHint: false);
        var arguments = TestArguments.From("""{ "path": "/etc/passwd" }""");

        Assert.Equal(
            Verdict.Deny,
            evaluator.Evaluate(new ToolCallFacts("fs__write_file", arguments, writable)).Verdict);

        // Each condition alone is enough to spare the call.
        Assert.Equal(
            Verdict.Allow,
            evaluator.Evaluate(new ToolCallFacts("git__commit", arguments, writable)).Verdict);

        Assert.Equal(
            Verdict.Allow,
            evaluator.Evaluate(new ToolCallFacts(
                "fs__write_file",
                arguments,
                new ToolAnnotationFacts(ReadOnlyHint: true))).Verdict);

        Assert.Equal(
            Verdict.Allow,
            evaluator.Evaluate(new ToolCallFacts(
                "fs__write_file",
                TestArguments.From("""{ "path": "/workspace/x" }"""),
                writable)).Verdict);
    }

    // ------------------------------------------------------------ explain trail

    [Fact]
    public void TheTrailNamesTheConditionThatFailed()
    {
        var evaluator = Evaluator(
            Deny("by-name", new PolicyMatch { Tool = "git__*" }),
            Deny("by-annotation", new PolicyMatch
            {
                Tool = "fs__*",
                Annotations = new AnnotationMatch { ReadOnlyHint = true },
            }),
            Deny("by-argument", new PolicyMatch
            {
                Tool = "fs__*",
                Arguments = [new ArgumentPredicate { Path = "$.limit", Gt = 100 }],
            }));

        var decision = evaluator.Evaluate(
            new ToolCallFacts(
                "fs__write_file",
                TestArguments.From("""{ "limit": 1 }"""),
                new ToolAnnotationFacts(ReadOnlyHint: false)),
            explain: true);

        Assert.NotNull(decision.Trail);

        // "no match" alone is useless on a rule with three conditions; the point
        // of --explain is knowing which one you got wrong.
        Assert.Collection(decision.Trail,
            line => Assert.Contains("'by-name': no match (tool)", line, StringComparison.Ordinal),
            line => Assert.Contains("'by-annotation': no match (annotations)", line, StringComparison.Ordinal),
            line => Assert.Contains("'by-argument': no match (argument $.limit)", line, StringComparison.Ordinal),
            line => Assert.Contains("default allow", line, StringComparison.Ordinal));
    }

    // --------------------------------------------------------- undecidable rules

    /// <summary>
    /// A pattern the caller can stall, and an argument long enough to stall it.
    /// </summary>
    private static PolicyEvaluator RegexEvaluator(params PolicyRule[] rules) => Evaluator(rules);

    private static readonly IReadOnlyDictionary<string, JsonElement> _stalling =
        TestArguments.From($$"""{ "path": "{{new string('a', 40)}}!" }""");

    [Fact]
    public void AnUndecidableRule_DeniesRatherThanFallingThroughToDefaultAllow()
    {
        // The bypass this closes: the model picks the argument, so if a timeout
        // read as "no match" it could pad any value until the deny rule gave up
        // and the call fell through to default-allow - with an audit record
        // indistinguishable from an ordinary allowed call.
        var evaluator = RegexEvaluator(
            Deny("no-secrets", new PolicyMatch
            {
                Arguments = [new ArgumentPredicate { Path = "$.path", Matches = "^(a+)+$" }],
            }));

        var decision = evaluator.Evaluate(new ToolCallFacts("fs__write_file", _stalling));

        Assert.Equal(Verdict.Deny, decision.Verdict);
        Assert.True(decision.IsBlocked);

        // The rule name reaches the audit record, so the skipped guardrail is
        // visible afterwards rather than silent.
        Assert.Equal("no-secrets", decision.RuleName);
        Assert.Contains("could not be evaluated", decision.Reason, StringComparison.Ordinal);
        Assert.Contains("$.path", decision.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUndecidableAllowRule_AlsoDenies()
    {
        // Fail closed regardless of the rule's own verdict: not knowing whether
        // an allow rule applies is not a reason to allow.
        var evaluator = RegexEvaluator(new PolicyRule
        {
            Name = "allow-safe-paths",
            Decision = Verdict.Allow,
            Match = new PolicyMatch
            {
                Arguments = [new ArgumentPredicate { Path = "$.path", Matches = "^(a+)+$" }],
            },
        });

        var decision = evaluator.Evaluate(new ToolCallFacts("fs__write_file", _stalling));

        Assert.Equal(Verdict.Deny, decision.Verdict);
    }

    [Fact]
    public void AnUndecidableRule_StopsTheWalkAndSaysSoInTheTrail()
    {
        // It stops rather than continuing to later rules: once a condition the
        // caller influences cannot be checked, no verdict below it is trustworthy.
        var evaluator = RegexEvaluator(
            Deny("undecidable", new PolicyMatch
            {
                Arguments = [new ArgumentPredicate { Path = "$.path", Matches = "^(a+)+$" }],
            }),
            new PolicyRule
            {
                Name = "allow-everything-else",
                Decision = Verdict.Allow,
                Match = PolicyMatch.Any,
            });

        var decision = evaluator.Evaluate(
            new ToolCallFacts("fs__write_file", _stalling),
            explain: true);

        Assert.Equal(Verdict.Deny, decision.Verdict);
        Assert.NotNull(decision.Trail);
        Assert.Collection(decision.Trail,
            line => Assert.Contains(
                "'undecidable': UNDECIDABLE (argument $.path) -> deny",
                line,
                StringComparison.Ordinal));
    }

    // ------------------------------------------------------------------ server

    [Fact]
    public void AServerConditionMatchesTheOwningServerByGlob()
    {
        var evaluator = Evaluator(Deny("no-github", new PolicyMatch { Server = "git*" }));

        Assert.Equal(
            Verdict.Deny,
            evaluator.Evaluate(new ToolCallFacts("github__create_issue", Server: "github")).Verdict);
        Assert.Equal(
            Verdict.Allow,
            evaluator.Evaluate(new ToolCallFacts("fs__read_file", Server: "fs")).Verdict);
    }

    [Fact]
    public void AServerConditionNeverMatchesAToolNoServerOwns()
    {
        // An unknown tool has no server. "*" would otherwise be the one server
        // pattern that reaches calls nobody serves.
        var evaluator = Evaluator(Deny("any-server", new PolicyMatch { Server = "*" }));

        var decision = evaluator.Evaluate(new ToolCallFacts("nobody__tool"), explain: true);

        Assert.Equal(Verdict.Allow, decision.Verdict);
        Assert.NotNull(decision.Trail);
        Assert.Contains(decision.Trail, l => l.Contains("no match (server)", StringComparison.Ordinal));
    }

    [Fact]
    public void AServerConditionCombinesWithAnnotations()
    {
        var evaluator = Evaluator(Deny("github-writes", new PolicyMatch
        {
            Server = "github",
            Annotations = new AnnotationMatch { ReadOnlyHint = false },
        }));

        var write = new ToolCallFacts("github__push", Server: "github");
        var read = new ToolCallFacts(
            "github__get_file", Server: "github", Annotations: new ToolAnnotationFacts(ReadOnlyHint: true));
        var otherWrite = new ToolCallFacts("fs__write_file", Server: "fs");

        Assert.Equal(Verdict.Deny, evaluator.Evaluate(write).Verdict);
        Assert.Equal(Verdict.Allow, evaluator.Evaluate(read).Verdict);
        Assert.Equal(Verdict.Allow, evaluator.Evaluate(otherWrite).Verdict);
    }
}
