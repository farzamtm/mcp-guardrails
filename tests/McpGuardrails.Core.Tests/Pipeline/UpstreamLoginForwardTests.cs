using System.Text.Json;
using System.Threading.Channels;
using McpGuardrails.Core.Audit;
using McpGuardrails.Core.Budget;
using McpGuardrails.Core.Pins;
using McpGuardrails.Core.Pipeline;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Scanners;
using McpGuardrails.Core.Tests.Upstream;
using McpGuardrails.Core.Upstream;
using McpGuardrails.Core.UpstreamAuth;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace McpGuardrails.Core.Tests.Pipeline;

/// <summary>
/// What the forward says when a remote server needs someone to run
/// <c>auth login</c>: before the session (its tools were never listed) and
/// during it (a refresh failed).
/// </summary>
public sealed class UpstreamLoginForwardTests
{
    /// <summary>A transport that works until a tool is called, then throws.</summary>
    private sealed class FailingOnCallTransport(IClientTransport inner, Exception failure) : IClientTransport
    {
        public string Name => inner.Name;

        public async Task<ITransport> ConnectAsync(CancellationToken cancellationToken = default) =>
            new Session(await inner.ConnectAsync(cancellationToken), failure);

        private sealed class Session(ITransport inner, Exception failure) : ITransport
        {
            public string? SessionId => inner.SessionId;

            public ChannelReader<JsonRpcMessage> MessageReader => inner.MessageReader;

            public Task SendMessageAsync(JsonRpcMessage message, CancellationToken cancellationToken = default) =>
                message is JsonRpcRequest { Method: RequestMethods.ToolsCall }
                    ? throw failure
                    : inner.SendMessageAsync(message, cancellationToken);

            public ValueTask DisposeAsync() => inner.DisposeAsync();
        }
    }

    private static McpServerTool Echo() =>
        McpServerTool.Create((string message) => message, new McpServerToolCreateOptions { Name = "echo" });

    private static GuardrailsCallPipeline Pipeline(UpstreamRegistry registry)
    {
        var document = PolicyDocument.Empty;
        var metadata = ToolMetadataGate.Build(document.EffectiveScanners.EffectiveInjection, []);

        return new GuardrailsCallPipeline(
            registry,
            new NullAuditSink(),
            new ToolCallTelemetry(),
            new PolicyEvaluator(document),
            metadata,
            ToolPinGate.Build(PinSettings.Disabled, [], metadata.Tools),
            new SecretGate(document.EffectiveScanners.EffectiveSecrets),
            new ArgumentGate(document.EffectiveScanners.EffectiveArguments),
            new BudgetGate(new InMemoryBudgetStore()),
            new InjectionGate(document.EffectiveScanners.EffectiveInjection));
    }

    private sealed class NullAuditSink : IAuditSink
    {
        public bool IsFaulted => false;

        public ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private static string Text(CallToolResult result) =>
        string.Concat(result.Content.OfType<TextContentBlock>().Select(block => block.Text));

    private static CallToolRequestParams Call(string name) => new()
    {
        Name = name,
        Arguments = new Dictionary<string, JsonElement> { ["message"] = JsonDocument.Parse("\"hi\"").RootElement.Clone() },
    };

    [Fact]
    public async Task ACallToAServerThatNeedsALogin_SaysWhatToRun()
    {
        await using var server = InMemoryMcpServer.Start("fixture", Echo());
        UpstreamTransportFactory factory = (config, logging) => config.Name == "linear"
            ? throw new UpstreamLoginRequiredException("linear", "has never been logged in")
            : server.TransportFactory(config, logging);

        await using var registry = await UpstreamRegistry.ConnectAsync(
            [new UpstreamServerConfig { Name = "fs", Command = "unused" }, new UpstreamServerConfig { Name = "linear", Command = "unused" }],
            NullLoggerFactory.Instance,
            factory);

        var result = await Pipeline(registry).ForwardAsync(Call("linear__create_issue"));

        Assert.True(result.IsError);
        Assert.Contains("belongs to server 'linear', which is not available", Text(result), StringComparison.Ordinal);
        Assert.Contains("run 'mcp-guardrails auth login linear'", Text(result), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ALoginLostMidSession_IsAToolError_NotAProtocolError()
    {
        await using var server = InMemoryMcpServer.Start("fixture", Echo());
        // How a refresh that failed reaches the forward: the SDK's OAuth handler
        // asked for a person, and the serving callback refused.
        var lost = new HttpRequestException("send failed", new UpstreamLoginRequiredException("linear", "needs a new login"));
        UpstreamTransportFactory factory = (config, logging) => new FailingOnCallTransport(server.TransportFactory(config, logging), lost);

        await using var registry = await UpstreamRegistry.ConnectAsync(
            [new UpstreamServerConfig { Name = "linear", Command = "unused" }],
            NullLoggerFactory.Instance,
            factory);

        var result = await Pipeline(registry).ForwardAsync(Call("linear__echo"));

        Assert.True(result.IsError);
        Assert.Contains("Refused 'linear__echo'", Text(result), StringComparison.Ordinal);
        Assert.Contains("auth login linear", Text(result), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnyOtherFailureMidCall_StillPropagates()
    {
        await using var server = InMemoryMcpServer.Start("fixture", Echo());
        UpstreamTransportFactory factory = (config, logging) =>
            new FailingOnCallTransport(server.TransportFactory(config, logging), new HttpRequestException("connection reset"));

        await using var registry = await UpstreamRegistry.ConnectAsync(
            [new UpstreamServerConfig { Name = "linear", Command = "unused" }],
            NullLoggerFactory.Instance,
            factory);

        var thrown = await Assert.ThrowsAnyAsync<Exception>(() => Pipeline(registry).ForwardAsync(Call("linear__echo")).AsTask());

        Assert.Null(UpstreamOAuth.LoginRequired(thrown));
    }
}
