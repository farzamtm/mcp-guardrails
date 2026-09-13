using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Policy;

public sealed class AnnotationMatchTests
{
    // -------------------------------------------------- the specification's defaults

    [Fact]
    public void AToolThatDeclaresNothing_CountsAsDestructiveAndOpenWorld()
    {
        // The fail-closed direction, and the reason annotation rules are worth
        // writing at all: a rule requiring approval for destructive tools also
        // covers every tool that never described itself.
        var undeclared = ToolAnnotationFacts.Undeclared;

        Assert.False(undeclared.IsReadOnly);
        Assert.True(undeclared.IsDestructive);
        Assert.False(undeclared.IsIdempotent);
        Assert.True(undeclared.IsOpenWorld);
    }

    [Fact]
    public void AReadOnlyTool_IsNeverDestructive()
    {
        // Per the MCP specification, destructiveHint only means anything when the
        // tool is not read-only. Honouring a stray "destructive: true" on a
        // read-only tool would make the two hints contradict each other.
        var facts = new ToolAnnotationFacts(ReadOnlyHint: true, DestructiveHint: true);

        Assert.False(facts.IsDestructive);
    }

    [Fact]
    public void DeclaredHints_AreUsedAsGiven()
    {
        var facts = new ToolAnnotationFacts(
            ReadOnlyHint: false,
            DestructiveHint: false,
            IdempotentHint: true,
            OpenWorldHint: false);

        Assert.False(facts.IsReadOnly);
        Assert.False(facts.IsDestructive);
        Assert.True(facts.IsIdempotent);
        Assert.False(facts.IsOpenWorld);
    }

    // ------------------------------------------------------------------ matching

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void ReadOnlyHint_MatchesBothWays(bool required, bool expected) =>
        Assert.Equal(
            expected,
            new AnnotationMatch { ReadOnlyHint = required }
                .Matches(new ToolAnnotationFacts(ReadOnlyHint: true)));

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void DestructiveHint_MatchesTheEffectiveValue(bool required, bool expected) =>
        Assert.Equal(
            expected,
            new AnnotationMatch { DestructiveHint = required }
                .Matches(new ToolAnnotationFacts(DestructiveHint: false)));

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void IdempotentHint_Matches(bool required, bool expected) =>
        Assert.Equal(
            expected,
            new AnnotationMatch { IdempotentHint = required }
                .Matches(new ToolAnnotationFacts(IdempotentHint: true)));

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void OpenWorldHint_Matches(bool required, bool expected) =>
        Assert.Equal(
            expected,
            new AnnotationMatch { OpenWorldHint = required }
                .Matches(new ToolAnnotationFacts(OpenWorldHint: false)));

    [Fact]
    public void SeveralHints_CombineWithAnd()
    {
        var match = new AnnotationMatch { ReadOnlyHint = false, OpenWorldHint = true };

        Assert.True(match.Matches(new ToolAnnotationFacts(ReadOnlyHint: false, OpenWorldHint: true)));
        Assert.False(match.Matches(new ToolAnnotationFacts(ReadOnlyHint: false, OpenWorldHint: false)));
        Assert.False(match.Matches(new ToolAnnotationFacts(ReadOnlyHint: true, OpenWorldHint: true)));
    }

    [Fact]
    public void UnspecifiedHints_AreIgnored()
    {
        var match = new AnnotationMatch { ReadOnlyHint = true };

        Assert.True(match.Matches(new ToolAnnotationFacts(
            ReadOnlyHint: true,
            DestructiveHint: true,
            IdempotentHint: true,
            OpenWorldHint: true)));
    }

    // ---------------------------------------------------------------- validation

    [Fact]
    public void Validate_RejectsAnEmptyBlock()
    {
        // "annotations:" with nothing under it reads like a filter but matches
        // everything, which is the opposite of what the author meant.
        var exception = Assert.Throws<PolicyException>(() => new AnnotationMatch().Validate("r"));

        Assert.Contains("empty 'annotations'", exception.Message, StringComparison.Ordinal);
        Assert.True(new AnnotationMatch().IsEmpty);
    }

    [Fact]
    public void Validate_AcceptsASingleHint()
    {
        new AnnotationMatch { DestructiveHint = true }.Validate("r");

        Assert.False(new AnnotationMatch { DestructiveHint = true }.IsEmpty);
    }
}
