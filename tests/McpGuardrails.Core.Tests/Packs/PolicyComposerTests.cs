using McpGuardrails.Core.Packs;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Packs;

public sealed class PolicyComposerTests
{
    private static readonly PolicyPack _alpha = PolicyPack.Parse(PolicyPackTests.PackText("alpha"));
    private static readonly PolicyPack _beta = PolicyPack.Parse(PolicyPackTests.PackText("beta"));

    [Fact]
    public void Compose_WritesALoadablePolicyWithEveryPacksRules_InOrder()
    {
        var text = PolicyComposer.Compose(
            [new PackAssignment(_alpha, "a", "r"), new PackAssignment(_beta, "b", "r")],
            []);

        var policy = PolicyLoader.Parse(text);
        Assert.Equal(["a-reads", "a-rest", "b-reads", "b-rest"], policy.EffectiveRules.Select(rule => rule.Name));
        Assert.Contains("#   alpha (version 1) for server 'a'", text);
        Assert.Contains("  # Pack: demo - protects nothing, allows reads.", text);
        Assert.Contains("  # - name: deny-everything-else", text);
        Assert.DoesNotContain("No pack covers", text);
        Assert.DoesNotContain(PolicyPack.Placeholder, text);
    }

    [Fact]
    public void Compose_NamesServersWithoutAPack()
    {
        var text = PolicyComposer.Compose([new PackAssignment(_alpha, "a", "r")], ["docs", "wiki"]);

        Assert.Contains("# No pack covers: docs, wiki.", text);
    }

    [Fact]
    public void Compose_IsDeterministic()
    {
        PackAssignment[] assignments = [new PackAssignment(_alpha, "a", "r")];

        Assert.Equal(PolicyComposer.Compose(assignments, []), PolicyComposer.Compose(assignments, []));
    }

    [Fact]
    public void Compose_NothingToWrite_Throws()
    {
        var ex = Assert.Throws<PackException>(() => PolicyComposer.Compose([], []));

        Assert.Contains("no packs", ex.Message);
    }
}
