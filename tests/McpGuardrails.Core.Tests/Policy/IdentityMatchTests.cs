using McpGuardrails.Core.Access;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Policy;

/// <summary>The <c>principal:</c> and <c>groups:</c> conditions, and when a policy may use them.</summary>
public sealed class IdentityMatchTests
{
    private const string _access = """
        access:
          oauth:
            issuer: https://login.example.com
            audience: api://mcp-guardrails

        """;

    private static PolicyEvaluator Evaluator(string rules) => new(PolicyLoader.Parse(_access + rules));

    private static Verdict Decide(PolicyEvaluator evaluator, string? principal, params string[] groups) =>
        evaluator.Evaluate(new ToolCallFacts(
            "fs__write_file",
            Caller: principal is null ? null : new CallerIdentity(principal, groups))).Verdict;

    [Fact]
    public void APrincipalGlob_MatchesTheCaller()
    {
        var evaluator = Evaluator("""
            rules:
              - name: example-staff
                match: { principal: "*@example.com" }
                decision: allow
              - name: rest
                decision: deny
            """);

        Assert.Equal(Verdict.Allow, Decide(evaluator, "alice@example.com"));
        Assert.Equal(Verdict.Deny, Decide(evaluator, "alice@example.org"));
    }

    [Fact]
    public void APrincipalGlob_IgnoresCase_SoADenyRuleCannotBeSteppedAround()
    {
        // Identity providers emit email-style principals in whatever case the
        // account was created with; a deny keyed on the lower-case domain must
        // still catch the same domain spelt differently.
        var evaluator = Evaluator("""
            rules:
              - name: contractors-read-only
                match: { principal: "*@contractor.example" }
                decision: deny
              - name: rest
                decision: allow
            """);

        Assert.Equal(Verdict.Deny, Decide(evaluator, "bob@Contractor.Example"));
        Assert.Equal(Verdict.Deny, Decide(evaluator, "BOB@CONTRACTOR.EXAMPLE"));
        Assert.Equal(Verdict.Allow, Decide(evaluator, "bob@contractor.example.org"));
    }

    [Fact]
    public void NoPrincipal_MatchesNoPrincipalCondition()
    {
        var evaluator = Evaluator("""
            rules:
              - name: anyone-named
                match: { principal: "*" }
                decision: allow
              - name: rest
                decision: deny
            """);

        Assert.Equal(Verdict.Deny, Decide(evaluator, null));
    }

    [Fact]
    public void Groups_MatchWhenTheCallerIsInAnyOfThem()
    {
        var evaluator = Evaluator("""
            rules:
              - name: writers
                match: { groups: [admins, engineering] }
                decision: allow
              - name: rest
                decision: deny
            """);

        Assert.Equal(Verdict.Allow, Decide(evaluator, "a", "guests", "engineering"));
        Assert.Equal(Verdict.Deny, Decide(evaluator, "a", "guests"));
        Assert.Equal(Verdict.Deny, Decide(evaluator, "a"));
        // Exact and case-sensitive, like every name the proxy compares.
        Assert.Equal(Verdict.Deny, Decide(evaluator, "a", "Admins"));
    }

    [Fact]
    public void TheExplainTrail_NamesTheIdentityCondition()
    {
        var evaluator = Evaluator("""
            rules:
              - name: alice-only
                match: { principal: alice }
                decision: allow
              - name: ops-only
                match: { groups: [ops] }
                decision: allow
            """);

        var trail = evaluator.Evaluate(new ToolCallFacts("fs__x", Caller: new CallerIdentity("bob", [])), explain: true).Trail!;

        Assert.Contains(trail, line => line.Contains("alice-only", StringComparison.Ordinal) && line.Contains("principal", StringComparison.Ordinal));
        Assert.Contains(trail, line => line.Contains("ops-only", StringComparison.Ordinal) && line.Contains("groups", StringComparison.Ordinal));
    }

    [Fact]
    public void AnIdentityCondition_IsNotACatchAll()
    {
        var match = PolicyLoader.Parse(_access + """
            rules:
              - name: r
                match: { principal: alice }
            """).EffectiveRules[0].EffectiveMatch;

        Assert.True(match.UsesIdentity);
        Assert.False(match.IsCatchAll);
        Assert.False(PolicyMatch.Any.UsesIdentity);
    }

    [Theory]
    [InlineData("principal: \"\"", "empty 'principal'")]
    [InlineData("groups: []", "empty 'groups'")]
    [InlineData("groups: [\"\"]", "empty 'groups'")]
    public void EmptyIdentityConditions_AreRefused(string condition, string expected)
    {
        var yaml = _access + $"rules:\n  - name: r\n    match: {{ {condition} }}";

        Assert.Contains(expected, Assert.Throws<PolicyException>(() => PolicyLoader.Parse(yaml)).Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("principal: alice")]
    [InlineData("groups: [ops]")]
    public void IdentityConditions_WithoutAccessOAuth_AreRefused(string condition)
    {
        // Without an identity source they could never match, and a deny rule
        // that never matches is a guardrail that is not there.
        var yaml = $"rules:\n  - name: ops-rule\n    match: {{ {condition} }}\n    decision: deny";

        var message = Assert.Throws<PolicyException>(() => PolicyLoader.Parse(yaml)).Message;

        Assert.Contains("Rule 'ops-rule'", message, StringComparison.Ordinal);
        Assert.Contains("'access.oauth'", message, StringComparison.Ordinal);
    }

    [Fact]
    public void APrincipalBudget_WithoutAccessOAuth_IsRefused()
    {
        var message = Assert.Throws<PolicyException>(
            () => PolicyLoader.Parse("budgets:\n  principal: { max_calls: 5 }")).Message;

        Assert.Contains("'budgets.principal' needs 'access.oauth'", message, StringComparison.Ordinal);
    }
}
