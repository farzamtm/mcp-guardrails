using McpGuardrails.Core.Packs;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Tests.Packs;

namespace McpGuardrails.Core.Tests.Policy;

public sealed class PolicyTestRunnerTests
{
    private const string _policy = """
        rules:
          - name: reads
            match: { server: fs, annotations: { readOnlyHint: true } }
            decision: allow
          - name: no-etc
            match:
              server: fs
              args: [{ path: $.path, prefix: /etc/ }]
            decision: deny
          - name: unknown-tools
            match: { tool: "*__nope" }
            decision: deny
        """;

    private static PolicyTestReport Run(string test, string policy = _policy) =>
        PolicyTestRunner.Run(PolicyTestRunner.Parse(test), policy);

    [Fact]
    public void PassingCases_Pass()
    {
        var report = Run("""
            policy: p.yaml
            tools:
              fs__read: { readOnlyHint: true }
              fs__write: { readOnlyHint: false }
            cases:
              - call: fs__read
                expect: allow
                rule: reads
              - call: fs__write
                args: { path: /etc/passwd }
                expect: deny
                rule: no-etc
              - name: an unlisted path falls through to the default
                call: fs__write
                args: { path: /tmp/x }
                expect: allow
            """);

        Assert.Equal(3, report.Cases.Count);
        Assert.Empty(report.Failures);
        Assert.All(report.Cases, c => Assert.Empty(c.Trail));
    }

    [Fact]
    public void WrongVerdict_FailsWithTheTrail()
    {
        var report = Run("""
            policy: p.yaml
            tools: { fs__write: {} }
            cases:
              - call: fs__write
                args: { path: /tmp/x }
                expect: deny
            """);

        var failure = Assert.Single(report.Failures);
        Assert.Equal("case 1 (fs__write)", failure.Label);
        Assert.Equal("expected deny, got allow from the default (no rule matched)", failure.Failure);
        Assert.Contains(failure.Trail, step => step.Contains("rule 'no-etc': no match"));
    }

    [Fact]
    public void WrongRule_Fails()
    {
        var report = Run("""
            policy: p.yaml
            tools: { fs__write: {} }
            cases:
              - name: named
                call: fs__write
                args: { path: /etc/x }
                expect: deny
                rule: reads
            """);

        var failure = Assert.Single(report.Failures);
        Assert.Equal("named", failure.Label);
        Assert.Equal("expected rule 'reads' to decide, but rule 'no-etc' did", failure.Failure);
    }

    [Fact]
    public void ArgumentDetectors_FromThePolicy_ApplyToTheDecision()
    {
        const string policy = """
            scanners:
              arguments:
                overrides:
                  - { tool: "web__*", action: block }
            """;

        var report = Run("""
            policy: p.yaml
            tools: { web__fetch: {}, fs__read: {} }
            cases:
              - call: web__fetch
                args: { url: "http://169.254.169.254/" }
                expect: deny
                rule: arguments.ssrf
                argument_hits: [ssrf]
              - name: audited elsewhere, so the verdict is unchanged
                call: fs__read
                args: { path: "../../etc/hosts", note: "http://localhost" }
                expect: allow
                argument_hits: [ssrf, path-traversal]
              - name: an empty list asserts that nothing fires
                call: fs__read
                args: { path: "src/main.cs" }
                expect: allow
                argument_hits: []
            """, policy);

        Assert.Empty(report.Failures);
    }

    [Fact]
    public void WrongArgumentHits_Fail()
    {
        var report = Run("""
            policy: p.yaml
            tools: { fs__write: {} }
            cases:
              - call: fs__write
                args: { path: "/tmp/../x" }
                expect: allow
                argument_hits: [ssrf]
            """);

        var failure = Assert.Single(report.Failures);
        Assert.Equal("expected argument hits [ssrf], got [path-traversal]", failure.Failure);
        Assert.Contains(failure.Trail, step => step.Contains("scanner 'arguments'"));
    }

    [Fact]
    public void ToolListedWithNoValue_AdvertisesNoHints()
    {
        // Undeclared hints are not read-only, so the reads rule does not apply.
        var report = Run("""
            policy: p.yaml
            tools:
              fs__read:
            cases:
              - call: fs__read
                expect: allow
                rule: reads
            """);

        Assert.Equal("expected rule 'reads' to decide, but the default (no rule matched) did", Assert.Single(report.Failures).Failure);
    }

    [Fact]
    public void UnknownTool_HasNoServer()
    {
        var report = Run("""
            policy: p.yaml
            cases:
              - call: fs__nope
                unknown: true
                args: { path: /etc/passwd }
                expect: deny
                rule: unknown-tools
            """);

        Assert.Empty(report.Failures);
    }

    [Fact]
    public void Pack_IsRenderedWithTheServer()
    {
        var report = Run(
            """
            policy: demo.yaml
            server: gh
            tools: { gh__get: { readOnlyHint: true }, gh__put: {} }
            cases:
              - call: gh__get
                expect: allow
                rule: gh-reads
              - call: gh__put
                expect: require_approval
                rule: gh-rest
            """,
            PolicyPackTests.PackText());

        Assert.Empty(report.Failures);
    }

    [Fact]
    public void Pack_WithoutServer_Throws()
    {
        var ex = Assert.Throws<PolicyException>(() => Run(
            "policy: demo.yaml\ncases: [{ call: gh__x, unknown: true, expect: allow }]",
            PolicyPackTests.PackText()));

        Assert.Contains("is a pack, so the test file needs 'server:'", ex.Message);
    }

    [Fact]
    public void BrokenPack_Throws()
    {
        var ex = Assert.Throws<PolicyException>(() => Run(
            "policy: demo.yaml\nserver: gh\ncases: [{ call: gh__x, unknown: true, expect: allow }]",
            PolicyPackTests.PackText(comment: "")));

        Assert.IsType<PackException>(ex.InnerException);
    }

    [Theory]
    [InlineData("policy: p\ntools: { fs__x: {} }\ncases: [{ expect: allow }]", "Case 1 needs 'call:'")]
    [InlineData("policy: p\ntools: { fs__x: {} }\ncases: [{ call: fs__x }]", "case 1 (fs__x): needs 'expect:'")]
    [InlineData("policy: p\ntools: { fs__x: {} }\ncases: [{ call: fs__x, unknown: true, expect: allow }]", "cannot be 'unknown: true'")]
    [InlineData("policy: p\ntools: { fs__x: {} }\ncases: [{ call: fs__y, expect: allow }]", "'fs__y' is not listed under 'tools:'")]
    [InlineData("policy: p\ncases: [{ call: fs__y, unknown: false, expect: allow }]", "'fs__y' is not listed under 'tools:'")]
    [InlineData("policy: p\ntools: { plain: {} }\ncases: [{ call: plain, expect: allow }]", "'plain' is not a qualified name")]
    [InlineData("policy: p\ntools: { __x: {} }\ncases: [{ call: __x, expect: allow }]", "'__x' is not a qualified name")]
    public void MalformedCase_Throws(string test, string expected)
    {
        var ex = Assert.Throws<PolicyException>(() => Run(test));

        Assert.Contains(expected, ex.Message);
    }

    [Theory]
    [InlineData("", "names the policy it tests")]
    [InlineData("cases: [{ call: a__b }]", "names the policy it tests")]
    [InlineData("policy: p.yaml", "at least one entry under 'cases:'")]
    [InlineData("policy: p.yaml\ncases: []", "at least one entry under 'cases:'")]
    [InlineData("policy: p.yaml\ncases: [{ call: a__b, expected: allow }]", "Test file is not valid")]
    [InlineData("policy: p.yaml\ncases: [{ call: a__b, expect: maybe }]", "Test file is not valid")]
    [InlineData("policy: p.yaml\ntools: { a__b: { readonlyhint: true } }\ncases: [{ call: a__b, expect: allow }]", "Test file is not valid")]
    [InlineData("policy: p\n bad: indent", "YAML syntax error")]
    public void MalformedFile_Throws(string test, string expected)
    {
        var ex = Assert.Throws<PolicyException>(() => PolicyTestRunner.Parse(test));

        Assert.Contains(expected, ex.Message);
    }

    [Fact]
    public void Run_ToleratesADocumentBuiltWithoutToolsOrCases()
    {
        var report = PolicyTestRunner.Run(new PolicyTestDocument { Policy = "p" }, _policy);

        Assert.Empty(report.Cases);
    }

    [Fact]
    public void ACase_CanNameTheCaller()
    {
        const string policy = """
            access:
              oauth:
                issuer: https://login.example.com
                audience: api://mcp-guardrails
            rules:
              - name: ops-write
                match: { server: fs, groups: [ops] }
                decision: allow
              - name: alice-write
                match: { server: fs, principal: alice }
                decision: allow
              - name: nobody-else
                decision: deny
            """;

        var report = Run("""
            policy: p.yaml
            tools: { fs__write: {} }
            cases:
              - call: fs__write
                principal: bob
                groups: [ops]
                expect: allow
                rule: ops-write
              - call: fs__write
                principal: alice
                expect: allow
                rule: alice-write
              - call: fs__write
                expect: deny
                rule: nobody-else
              - call: fs__nope
                unknown: true
                principal: alice
                expect: deny
            """, policy);

        Assert.Empty(report.Failures);
    }
}
