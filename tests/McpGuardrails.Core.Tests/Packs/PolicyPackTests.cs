using McpGuardrails.Core.Packs;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Tests.Packs;

public sealed class PolicyPackTests
{
    /// <summary>A minimal valid pack, with the parts tests vary as parameters.</summary>
    internal static string PackText(
        string name = "demo",
        string header = "pack:\n  name: {0}\n  version: 1\n  description: A demo pack.\n  recognizes: [demo-server, https://demo.example.com/mcp]\n",
        string rules = "  - name: \"{{server}}-reads\"\n    match: { server: \"{{server}}\", annotations: { readOnlyHint: true } }\n    decision: allow\n  - name: \"{{server}}-rest\"\n    match: { server: \"{{server}}\" }\n    decision: require_approval\n",
        string comment = "# Pack: demo - protects nothing, allows reads.\n") =>
        comment + string.Format(header, name) + "\nrules:\n" + rules;

    private static UpstreamServerConfig Stdio(string template) =>
        new() { Name = "s", Command = "x", DisplayTemplate = template };

    [Fact]
    public void Parse_ReadsTheHeaderAndComment()
    {
        var pack = PolicyPack.Parse(PackText());

        Assert.Equal("demo", pack.Name);
        Assert.Equal(1, pack.Version);
        Assert.Equal("A demo pack.", pack.Description);
        Assert.Equal(["demo-server", "https://demo.example.com/mcp"], pack.Recognizes);
        Assert.Equal("# Pack: demo - protects nothing, allows reads.", pack.Comment);
    }

    [Fact]
    public void Parse_AcceptsCrLfAndTrailingBlankLines()
    {
        var pack = PolicyPack.Parse(PackText().Replace("\n", "\r\n") + "\r\n\r\n");

        Assert.Equal("  decision: require_approval".Trim(), pack.RenderRules("gh")[^1].Trim());
    }

    [Fact]
    public void Parse_WithoutRecognizes_RecognizesNothing()
    {
        var pack = PolicyPack.Parse(PackText(header: "pack:\n  name: {0}\n  version: 2\n  description: d\n"));

        Assert.Empty(pack.Recognizes);
        Assert.Null(pack.Recognize(Stdio("demo-server")));
    }

    [Theory]
    [InlineData("", "starts with a comment")]
    [InlineData("\n\n", "starts with a comment")]
    public void Parse_WithoutHeaderComment_Throws(string comment, string expected)
    {
        var ex = Assert.Throws<PackException>(() => PolicyPack.Parse(PackText(comment: comment)));

        Assert.Contains(expected, ex.Message);
    }

    [Fact]
    public void Parse_WithoutRulesLine_Throws()
    {
        var ex = Assert.Throws<PackException>(() =>
            PolicyPack.Parse("# c\npack:\n  name: x\n  version: 1\n  description: d\n"));

        Assert.Contains("top-level 'rules:'", ex.Message);
    }

    [Fact]
    public void Parse_WithASectionAfterRules_Throws()
    {
        var ex = Assert.Throws<PackException>(() =>
            PolicyPack.Parse(PackText() + "budgets:\n  session: { max_calls: 1 }\n"));

        Assert.Contains("must be the last section", ex.Message);
        Assert.Contains("'budgets:'", ex.Message);
    }

    [Fact]
    public void Parse_InvalidYaml_Throws()
    {
        var ex = Assert.Throws<PackException>(() =>
            PolicyPack.Parse("# c\npack:\n  name: x\n bad: y\nrules:\n  - x"));

        Assert.Contains("YAML syntax error", ex.Message);
    }

    [Fact]
    public void Parse_RootThatIsNotAMapping_Throws()
    {
        var ex = Assert.Throws<PackException>(() => PolicyPack.Parse("# c\n[a,\nrules:\n  b]\n"));

        Assert.Contains("is a mapping", ex.Message);
    }

    [Fact]
    public void Parse_ExtraTopLevelKeys_Throws()
    {
        var text = "# c\nscanners:\n  injection: { action: block }\n" + PackText(comment: "");

        var ex = Assert.Throws<PackException>(() => PolicyPack.Parse(text));

        Assert.Contains("remove 'scanners'", ex.Message);
    }

    [Theory]
    [InlineData("pack: just-a-string\n", "'pack:' section is not valid")]
    [InlineData("pack:\n  name: {0}\n  version: 1\n  description: d\n  recognises: [x]\n", "'pack:' section is not valid")]
    [InlineData("pack:\n", "needs a 'pack:' section")]
    [InlineData("other: 1\n", "remove 'other'")]
    [InlineData("pack:\n  version: 1\n  description: d\n", "'pack.name'")]
    [InlineData("pack:\n  name: has_underscore\n  version: 1\n  description: d\n", "'pack.name'")]
    [InlineData("pack:\n  name: {0}\n  description: d\n", "positive 'pack.version'")]
    [InlineData("pack:\n  name: {0}\n  version: 0\n  description: d\n", "positive 'pack.version'")]
    [InlineData("pack:\n  name: {0}\n  version: 1\n", "one-line 'pack.description'")]
    [InlineData("pack:\n  name: {0}\n  version: 1\n  description: d\n  recognizes: ['']\n", "empty entry")]
    public void Parse_BadHeader_Throws(string header, string expected)
    {
        var ex = Assert.Throws<PackException>(() => PolicyPack.Parse(PackText(header: header)));

        Assert.Contains(expected, ex.Message);
    }

    [Fact]
    public void Parse_NoRules_Throws()
    {
        var ex = Assert.Throws<PackException>(() => PolicyPack.Parse(PackText(rules: "  []\n")));

        Assert.Contains("has no rules", ex.Message);
    }

    [Fact]
    public void Parse_RuleNotScopedToTheServer_Throws()
    {
        var rules = "  - name: \"{{server}}-everything\"\n    decision: deny\n";

        var ex = Assert.Throws<PackException>(() => PolicyPack.Parse(PackText(rules: rules)));

        Assert.Contains("missing on 'example-everything'", ex.Message);
    }

    [Fact]
    public void Parse_DuplicateRuleNames_Throws()
    {
        var rule = "  - name: \"{{server}}-a\"\n    match: { server: \"{{server}}\" }\n    decision: deny\n";

        var ex = Assert.Throws<PackException>(() => PolicyPack.Parse(PackText(rules: rule + rule)));

        Assert.Contains("more than one rule named 'example-a'", ex.Message);
    }

    [Fact]
    public void Parse_RuleNameWithoutPlaceholder_Throws()
    {
        var rules = "  - name: fixed\n    match: { server: \"{{server}}\" }\n    decision: deny\n";

        var ex = Assert.Throws<PackException>(() => PolicyPack.Parse(PackText(rules: rules)));

        Assert.Contains("rule 'fixed' needs '{{server}}' in its name", ex.Message);
    }

    [Fact]
    public void Parse_RuleThatDoesNotLoad_Throws()
    {
        var rules = "  - name: \"{{server}}-a\"\n    match: { server: \"{{server}}\" }\n    decision: maybe\n";

        var ex = Assert.Throws<PackException>(() => PolicyPack.Parse(PackText(rules: rules)));

        Assert.Contains("does not load as a policy", ex.Message);
        Assert.IsType<PolicyException>(ex.InnerException);
    }

    [Fact]
    public void RenderRules_ReplacesThePlaceholder()
    {
        var lines = PolicyPack.Parse(PackText()).RenderRules("gh");

        Assert.Contains("  - name: \"gh-reads\"", lines);
        Assert.DoesNotContain(lines, line => line.Contains(PolicyPack.Placeholder));
    }

    [Theory]
    [InlineData("")]
    [InlineData("a b")]
    [InlineData("a\"\n  - name: injected")]
    [InlineData("under_score")]
    public void RenderRules_RefusesNamesThatCouldChangeTheYaml(string server)
    {
        var pack = PolicyPack.Parse(PackText());

        var ex = Assert.Throws<PackException>(() => pack.RenderRules(server));

        Assert.Contains("not a valid server name", ex.Message);
    }

    [Fact]
    public void RenderPolicy_ScopesEveryRuleToTheServer()
    {
        var policy = PolicyPack.Parse(PackText()).RenderPolicy("gh");

        Assert.All(policy.EffectiveRules, rule => Assert.Equal("gh", rule.EffectiveMatch.Server));
        Assert.Equal(["gh-reads", "gh-rest"], policy.EffectiveRules.Select(rule => rule.Name));
    }

    [Theory]
    [InlineData("# c\npack:\n  name: x\nrules:\n", true)]
    [InlineData("rules:\n  - name: a\n", false)]
    [InlineData("rules:\n  - name: pack:\n", false)]
    public void IsPack_LooksForATopLevelPackKey(string text, bool expected) =>
        Assert.Equal(expected, PolicyPack.IsPack(text));

    [Theory]
    [InlineData("demo-server", "demo-server")]
    [InlineData("npx -y demo-server@1.2.3 /tmp", "demo-server")]
    [InlineData("docker run -i --rm ghcr.io/acme/demo-server@sha256:abc", "demo-server")]
    [InlineData("docker run -i --rm ghcr.io/acme/demo-server:latest", "demo-server")]
    [InlineData("/usr/local/bin/demo-server --stdio", "demo-server")]
    [InlineData("C:\\tools\\demo-server.exe", "demo-server")]
    [InlineData("uvx \"demo-server==2026.1.1\"", "demo-server")]
    [InlineData("DEMO-SERVER", "demo-server")]
    [InlineData("https://demo.example.com/mcp", "https://demo.example.com/mcp")]
    [InlineData("https://demo.example.com/mcp/v2", "https://demo.example.com/mcp")]
    public void Recognize_MatchesWholeNamesAndUrlPrefixes(string template, string expected) =>
        Assert.Equal(expected, PolicyPack.Parse(PackText()).Recognize(Stdio(template)));

    [Theory]
    [InlineData("npx -y demo-server-extra")]
    [InlineData("npx -y not-demo-server")]
    [InlineData("https://other.example.com/mcp")]
    [InlineData("")]
    public void Recognize_DoesNotMatchSubstrings(string template) =>
        Assert.Null(PolicyPack.Parse(PackText()).Recognize(Stdio(template)));

    [Fact]
    public void Recognize_FallsBackToTheUrl_ThenToNothing()
    {
        var pack = PolicyPack.Parse(PackText());

        Assert.Equal(
            "https://demo.example.com/mcp",
            pack.Recognize(new UpstreamServerConfig
            {
                Name = "r",
                Transport = UpstreamTransport.Http,
                Url = new Uri("https://demo.example.com/mcp"),
            }));
        Assert.Null(pack.Recognize(new UpstreamServerConfig { Name = "n", Command = "demo-server" }));
    }

    [Theory]
    [InlineData("pkg", "pkg")]
    [InlineData("pkg@1.2", "pkg")]
    [InlineData("@scope/pkg", "@scope/pkg")]
    [InlineData("@scope/pkg@1.2", "@scope/pkg")]
    [InlineData("pkg==1.2", "pkg")]
    [InlineData("image:tag", "image")]
    [InlineData("localhost:5000/image", "localhost:5000/image")]
    [InlineData("localhost:5000/image:tag", "localhost:5000/image")]
    [InlineData("C:", "C:")]
    [InlineData("tool.EXE", "tool")]
    public void WithoutVersion_StripsVersionSuffixes(string word, string expected) =>
        Assert.Equal(expected, PolicyPack.WithoutVersion(word));

    [Fact]
    public void PackException_KeepsItsCause()
    {
        var cause = new InvalidOperationException("inner");

        Assert.Same(cause, new PackException("outer", cause).InnerException);
    }
}
