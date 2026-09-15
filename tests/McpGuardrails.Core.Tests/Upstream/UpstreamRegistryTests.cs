using System.ComponentModel;
using System.Text.Json;
using McpGuardrails.Core.Upstream;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace McpGuardrails.Core.Tests.Upstream;

/// <summary>
/// Integration tests for the client half of the proxy, run against a real MCP
/// server hosted in-process (see <see cref="InMemoryMcpServer"/>).
/// </summary>
public sealed class UpstreamRegistryTests
{
    private static UpstreamServerConfig Config(string name) => new()
    {
        Name = name,
        Command = "unused-because-the-transport-is-injected",
    };

    private static McpServerTool EchoTool() => McpServerTool.Create(
        [Description("Echoes a message back.")]
    ([Description("Message to echo.")] string message) => $"echo: {message}",
        new McpServerToolCreateOptions { Name = "echo" });

    private static McpServerTool DestructiveTool() => McpServerTool.Create(
        () => "deleted",
        new McpServerToolCreateOptions
        {
            Name = "delete_everything",
            // Annotations must survive namespacing - the policy engine matches on
            // them in step 5.
            Destructive = true,
            ReadOnly = false,
        });

    [Fact]
    public async Task ConnectAsync_DiscoversAndNamespacesDownstreamTools()
    {
        await using var server = InMemoryMcpServer.Start("fixture", EchoTool(), DestructiveTool());

        await using var registry = await UpstreamRegistry.ConnectAsync(
            [Config("fs")], NullLoggerFactory.Instance, server.TransportFactory);

        var connection = Assert.Single(registry.Connections);
        Assert.Equal("fs", connection.Name);
        Assert.Equal(2, connection.Tools.Count);
        Assert.Contains(connection.Tools, t => t.Name == "echo");
    }

    [Fact]
    public async Task TryResolve_MapsQualifiedNameToDownstreamTool()
    {
        await using var server = InMemoryMcpServer.Start("fixture", EchoTool());

        await using var registry = await UpstreamRegistry.ConnectAsync(
            [Config("fs")], NullLoggerFactory.Instance, server.TransportFactory);

        Assert.True(registry.TryResolve("fs__echo", out var connection, out var toolName));
        Assert.Equal("fs", connection.Name);
        Assert.Equal("echo", toolName);
    }

    [Theory]
    [InlineData("echo")]              // un-namespaced
    [InlineData("other__echo")]       // wrong server
    [InlineData("fs__nope")]          // unknown tool
    [InlineData("")]
    public async Task TryResolve_RejectsUnknownNames(string requested)
    {
        await using var server = InMemoryMcpServer.Start("fixture", EchoTool());

        await using var registry = await UpstreamRegistry.ConnectAsync(
            [Config("fs")], NullLoggerFactory.Instance, server.TransportFactory);

        Assert.False(registry.TryResolve(requested, out _, out var toolName));
        Assert.Empty(toolName);
    }

    /// <summary>
    /// End-to-end through the real protocol: resolve a namespaced name and invoke
    /// it on the downstream server.
    /// </summary>
    [Fact]
    public async Task ResolvedTool_CanActuallyBeCalled()
    {
        await using var server = InMemoryMcpServer.Start("fixture", EchoTool());

        await using var registry = await UpstreamRegistry.ConnectAsync(
            [Config("fs")], NullLoggerFactory.Instance, server.TransportFactory);

        Assert.True(registry.TryResolve("fs__echo", out var connection, out var downstreamName));

        var result = await connection.Client.CallToolAsync(new CallToolRequestParams
        {
            Name = downstreamName,
            // JsonDocument.Parse rather than JsonSerializer.SerializeToElement:
            // the latter is reflection-based and the AOT analyzers reject it,
            // which is the whole point of having IsAotCompatible switched on.
            Arguments = new Dictionary<string, JsonElement>
            {
                ["message"] = JsonDocument.Parse("\"hi\"").RootElement.Clone(),
            },
        });

        // IsError is bool? - absent means success on the wire, so it arrives as
        // null rather than false. Assert.False(null) fails, hence the explicit
        // comparison. Program.cs relies on the same nullability (`is true`).
        Assert.NotEqual(true, result.IsError);
        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content));
        Assert.Equal("echo: hi", text.Text);
    }

    [Fact]
    public async Task TryGetTool_ReturnsTheDefinitionThePolicyEngineMatchesOn()
    {
        await using var server = InMemoryMcpServer.Start("fixture", DestructiveTool());

        await using var registry = await UpstreamRegistry.ConnectAsync(
            [Config("fs")], NullLoggerFactory.Instance, server.TransportFactory);

        Assert.True(registry.TryGetTool("fs__delete_everything", out var tool));

        // The downstream name on the DTO, and the annotations policy rules match
        // on. Without these arriving here, every annotation rule would silently
        // see an undeclared tool.
        Assert.Equal("delete_everything", tool.Name);
        Assert.True(tool.Annotations?.DestructiveHint);
    }

    [Theory]
    [InlineData("delete_everything")]  // un-namespaced
    [InlineData("fs__nope")]           // unknown tool
    public async Task TryGetTool_ReturnsFalseForAnUnknownName(string requested)
    {
        await using var server = InMemoryMcpServer.Start("fixture", DestructiveTool());

        await using var registry = await UpstreamRegistry.ConnectAsync(
            [Config("fs")], NullLoggerFactory.Instance, server.TransportFactory);

        Assert.False(registry.TryGetTool(requested, out var tool));

        // Null, not a non-nullable reference the analyzer has been told to trust.
        // The CLI passes this straight into PolicyFacts.ForCall, which accepts an
        // absent tool; a lie here would only surface as a crash on the call path.
        Assert.Null(tool);
    }

    [Fact]
    public async Task ConnectAsync_PreservesToolAnnotationsThroughDiscovery()
    {
        await using var server = InMemoryMcpServer.Start("fixture", DestructiveTool());

        await using var registry = await UpstreamRegistry.ConnectAsync(
            [Config("fs")], NullLoggerFactory.Instance, server.TransportFactory);

        var tool = Assert.Single(registry.Connections).Tools
            .Single(t => t.Name == "delete_everything");

        Assert.True(tool.ProtocolTool.Annotations?.DestructiveHint);
    }

    [Fact]
    public async Task ConnectAsync_RejectsDuplicateServerNames()
    {
        await using var server = InMemoryMcpServer.Start("fixture", EchoTool());

        var exception = await Assert.ThrowsAsync<ArgumentException>(
            async () => await UpstreamRegistry.ConnectAsync(
                [Config("fs"), Config("fs")],
                NullLoggerFactory.Instance,
                server.TransportFactory));

        Assert.Contains("Duplicate", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConnectAsync_ValidatesEveryConfigBeforeConnecting()
    {
        await using var server = InMemoryMcpServer.Start("fixture", EchoTool());

        // Underscores are illegal in server names; validation must reject this
        // before any transport is opened.
        var bad = new UpstreamServerConfig { Name = "bad_name", Command = "x" };

        await Assert.ThrowsAsync<ArgumentException>(
            async () => await UpstreamRegistry.ConnectAsync(
                [bad], NullLoggerFactory.Instance, server.TransportFactory));
    }

    [Fact]
    public async Task ConnectAsync_RejectsNullArguments()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            async () => await UpstreamRegistry.ConnectAsync(null!, NullLoggerFactory.Instance));

        await Assert.ThrowsAsync<ArgumentNullException>(
            async () => await UpstreamRegistry.ConnectAsync([], null!));
    }

    [Fact]
    public async Task ConnectAsync_WithNoConfigs_YieldsEmptyRegistry()
    {
        await using var registry = await UpstreamRegistry.ConnectAsync(
            [], NullLoggerFactory.Instance);

        Assert.Empty(registry.Connections);
        Assert.False(registry.TryResolve("fs__echo", out _, out _));
    }

    [Fact]
    public async Task DisposeAsync_IsIdempotent()
    {
        await using var server = InMemoryMcpServer.Start("fixture", EchoTool());

        var registry = await UpstreamRegistry.ConnectAsync(
            [Config("fs")], NullLoggerFactory.Instance, server.TransportFactory);

        await registry.DisposeAsync();
        await registry.DisposeAsync(); // must not throw
    }
}
