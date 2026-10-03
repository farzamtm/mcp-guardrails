using McpGuardrails.Core.Upstream;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Tests.Upstream;

/// <summary>
/// ToolNamespacer is pure string/DTO manipulation with no I/O, which is exactly
/// why it is worth testing exhaustively: the tests are fast and total.
/// </summary>
/// <remarks>
/// xUnit notes:
/// - [Fact] is a test with no arguments.
/// - [Theory] + [InlineData] is a parameterised test; each InlineData row runs as
///   its own separate test case, so one bad row doesn't hide the others.
/// </remarks>
public sealed class ToolNamespacerTests
{
    [Fact]
    public void Qualify_JoinsServerAndToolName()
    {
        Assert.Equal("fs__read_file", ToolNamespacer.Qualify("fs", "read_file"));
    }

    [Fact]
    public void TrySplit_RoundTripsQualifiedName()
    {
        var qualified = ToolNamespacer.Qualify("fs", "read_file");

        Assert.True(ToolNamespacer.TrySplit(qualified, out var server, out var tool));
        Assert.Equal("fs", server);
        Assert.Equal("read_file", tool);
    }

    [Fact]
    public void TrySplit_SplitsOnFirstSeparatorSoToolNamesMayContainIt()
    {
        // Server names forbid underscores, tool names do not. Splitting on the
        // first separator is what makes the round trip unambiguous.
        Assert.True(ToolNamespacer.TrySplit("fs__read__file", out var server, out var tool));
        Assert.Equal("fs", server);
        Assert.Equal("read__file", tool);
    }

    [Theory]
    [InlineData("read_file")]      // no separator at all
    [InlineData("__read_file")]    // empty server name
    [InlineData("fs__")]           // empty tool name
    [InlineData("")]
    public void TrySplit_RejectsMalformedNames(string input)
    {
        Assert.False(ToolNamespacer.TrySplit(input, out var server, out var tool));
        Assert.Empty(server);
        Assert.Empty(tool);
    }

    /// <summary>
    /// Regression test for a bug that shipped in the first pass-through proxy.
    /// </summary>
    /// <remarks>
    /// The first implementation used McpClientTool.WithName(), which renames only
    /// the client-side wrapper and leaves the underlying ProtocolTool untouched.
    /// The result: tools/list advertised "write_file" while tools/call only
    /// accepted "fs__write_file", so every tool the client could see was
    /// uncallable. Asserting on the copied DTO's Name pins the real contract.
    /// </remarks>
    [Fact]
    public void Qualify_Tool_RenamesTheProtocolDto()
    {
        var source = new Tool { Name = "write_file", Description = "writes" };

        var qualified = ToolNamespacer.Qualify("fs", source);

        Assert.Equal("fs__write_file", qualified.Name);
        Assert.Equal("write_file", source.Name); // original must not be mutated
    }

    [Fact]
    public void Qualify_Tool_PreservesAnnotationsAndSchema()
    {
        // Annotations drive policy decisions, so losing them here would
        // silently disable the destructive-tool rules.
        var source = new Tool
        {
            Name = "write_file",
            Title = "Write File",
            Description = "writes",
            Annotations = new ToolAnnotations { DestructiveHint = true, ReadOnlyHint = false },
        };

        var qualified = ToolNamespacer.Qualify("fs", source);

        Assert.Equal("Write File", qualified.Title);
        Assert.Equal("writes", qualified.Description);
        Assert.NotNull(qualified.Annotations);
        Assert.True(qualified.Annotations.DestructiveHint);
        Assert.Equal(source.InputSchema, qualified.InputSchema);
    }

    [Fact]
    public void Qualify_Tool_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(
            () => ToolNamespacer.Qualify("fs", (Tool)null!));
    }
}
