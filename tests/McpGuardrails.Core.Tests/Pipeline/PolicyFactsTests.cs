using System.Text.Json;
using McpGuardrails.Core.Pipeline;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Tests.Pipeline;

/// <summary>
/// The seam between the protocol and the policy engine. Small, but the only
/// place a mistake would make every annotation rule silently stop matching.
/// </summary>
public sealed class PolicyFactsTests
{
    private static Tool ToolWith(ToolAnnotations? annotations) =>
        new() { Name = "write_file", Annotations = annotations };

    [Fact]
    public void ForCall_CopiesTheToolsAnnotations()
    {
        var tool = ToolWith(new ToolAnnotations
        {
            ReadOnlyHint = false,
            DestructiveHint = true,
            IdempotentHint = false,
            OpenWorldHint = true,
        });

        var facts = PolicyFacts.ForCall("fs__write_file", null, tool);

        Assert.NotNull(facts.Annotations);
        Assert.False(facts.Annotations.ReadOnlyHint);
        Assert.True(facts.Annotations.DestructiveHint);
        Assert.False(facts.Annotations.IdempotentHint);
        Assert.True(facts.Annotations.OpenWorldHint);
    }

    [Fact]
    public void ForCall_CarriesTheOwningServer_WhenThereIsOne()
    {
        Assert.Equal("fs", PolicyFacts.ForCall("fs__write_file", null, null, "fs").Server);
        Assert.Null(PolicyFacts.ForCall("fs__write_file", null, null).Server);
    }

    [Fact]
    public void ForCall_PreservesUndeclaredHintsAsUndeclared()
    {
        // null is not false. The two produce different effective values, and
        // flattening them here would quietly disarm the fail-closed defaults.
        var facts = PolicyFacts.ForCall(
            "fs__write_file",
            null,
            ToolWith(new ToolAnnotations { ReadOnlyHint = false }));

        Assert.NotNull(facts.Annotations);
        Assert.Null(facts.Annotations.DestructiveHint);
        Assert.True(facts.EffectiveAnnotations.IsDestructive);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ForCall_YieldsNoAnnotationsWhenThereAreNone(bool unknownTool)
    {
        var facts = PolicyFacts.ForCall(
            "fs__write_file",
            null,
            unknownTool ? null : ToolWith(null));

        Assert.Null(facts.Annotations);

        // An unknown or silent tool still gets the specification's defaults, so a
        // blanket destructive rule covers it.
        Assert.True(facts.EffectiveAnnotations.IsDestructive);
    }

    [Fact]
    public void ForCall_CarriesTheToolNameAndArguments()
    {
        var request = new CallToolRequestParams
        {
            Name = "write_file",
            Arguments = new Dictionary<string, JsonElement>
            {
                ["path"] = JsonDocument.Parse("\"/etc/passwd\"").RootElement.Clone(),
            },
        };

        var facts = PolicyFacts.ForCall("fs__write_file", request, ToolWith(null));

        // The namespaced name, not the downstream one: rules are written against
        // what the client sees.
        Assert.Equal("fs__write_file", facts.ToolName);
        Assert.NotNull(facts.Arguments);
        Assert.Equal("/etc/passwd", facts.Arguments["path"].GetString());
    }

    [Fact]
    public void ForCall_HandlesACallWithNoArguments()
    {
        var facts = PolicyFacts.ForCall("fs__list_roots", new CallToolRequestParams
        {
            Name = "list_roots",
        }, null);

        Assert.Null(facts.Arguments);
    }
}
