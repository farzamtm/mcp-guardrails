using McpGuardrails.Core.Scanners;
using McpGuardrails.Core.Tests.Upstream;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Tests.Scanners;

/// <summary>
/// Tests for the <c>scan</c> command line, and for the one-server document a
/// <c>--command</c> or <c>--url</c> target becomes.
/// </summary>
public sealed class ScanOptionsTests
{
    private static UpstreamServerConfig Target(params string[] args)
    {
        var document = ScanOptions.Parse(args).TargetDocument;
        Assert.NotNull(document);

        var result = ServersLoader.Parse(document, FakeHost.At("work"), new FakeHost().Build());
        Assert.True(result.IsValid, string.Join("\n", result.Errors));

        var server = Assert.Single(result.Servers);
        Assert.Equal(ScanOptions.TargetName, server.Name);
        return server;
    }

    private static string Error(params string[] args) =>
        Assert.Throws<ScanOptionsException>(() => ScanOptions.Parse(args)).Message;

    [Fact]
    public void Null_IsRejected() =>
        Assert.Throws<ArgumentNullException>(() => ScanOptions.Parse(null!));

    [Fact]
    public void NoFlags_ScanTheConfiguredServersAsText()
    {
        var options = ScanOptions.Parse(["scan"]);

        Assert.Equal((false, null, null), (options.Json, options.ServersPath, options.TargetDocument));
        Assert.Equal(ScanOptions.DefaultTimeout, options.Timeout);
    }

    [Fact]
    public void TheSubcommand_MayStandAnywhereBeforeCommand() =>
        Assert.True(ScanOptions.Parse(["--json", "scan"]).Json);

    [Theory]
    [InlineData("scan", "servers.yaml", "--json")] // --servers forgotten
    [InlineData("scan", "--json", "-json")] // a single-dash flag
    [InlineData("scan", "scan")]
    public void AStrayWord_IsAnError_SoTheWrongThingIsNeverScanned(params string[] args)
    {
        var message = Error(args);

        Assert.Contains("--servers <path>", message, StringComparison.Ordinal);
        Assert.DoesNotContain("servers.yaml", message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--servers", "a.yaml", "--servers", "b.yaml")]
    [InlineData("--url", "https://a.example/mcp", "--url", "https://b.example/mcp")]
    [InlineData("--timeout", "5", "--timeout", "9")]
    public void ASingleValueFlagGivenTwice_IsAnError(params string[] flags) =>
        Assert.Equal($"{flags[0]} was given more than once.", Error(["scan", .. flags]));

    [Fact]
    public void ATimeout_IsReadInSeconds() =>
        Assert.Equal(TimeSpan.FromSeconds(5), ScanOptions.Parse(["scan", "--timeout", "5"]).Timeout);

    [Theory]
    [InlineData("0")]
    [InlineData("-1")]
    [InlineData("3601")]
    [InlineData("1.5")]
    [InlineData("soon")]
    public void ATimeoutThatIsNotASensibleWholeNumber_IsAnError(string value) =>
        Assert.Contains("whole number of seconds", Error("scan", "--timeout", value), StringComparison.Ordinal);

    [Fact]
    public void JsonAndServers_AreRead()
    {
        var options = ScanOptions.Parse(["scan", "--json", "--servers", "team.yaml"]);

        Assert.True(options.Json);
        Assert.Equal("team.yaml", options.ServersPath);
        Assert.Null(options.TargetDocument);
    }

    [Fact]
    public void AnUnknownFlag_IsAnError() =>
        Assert.Contains("'--sever'", Error("scan", "--sever", "x.yaml"), StringComparison.Ordinal);

    [Theory]
    [InlineData("--servers")]
    [InlineData("--url")]
    [InlineData("--header")]
    public void AFlagWithoutItsValue_IsAnError(string flag)
    {
        Assert.Equal($"{flag} needs a value.", Error("scan", flag));
        Assert.Equal($"{flag} needs a value.", Error("scan", flag, "--json"));
    }

    [Fact]
    public void ACommandTarget_TakesTheRestOfTheLine_AndRunsIsolated()
    {
        var server = Target("scan", "--json", "--command", "npx", "-y", "pkg@1.2.3", "--json", "--servers");

        Assert.Equal(UpstreamTransport.Stdio, server.Transport);
        Assert.EndsWith("npx", server.Command, StringComparison.Ordinal);
        Assert.Equal(["-y", "pkg@1.2.3", "--json", "--servers"], server.Arguments);
        Assert.False(server.InheritEnvironment);

        // The flags after --command belong to the server, not to scan.
        Assert.True(ScanOptions.Parse(["scan", "--command", "npx", "--json"]).Json is false);
    }

    [Fact]
    public void ADollarLeftByTheShell_IsKeptLiterally() =>
        Assert.Equal(["$HOME/x", "${NOPE}"], Target("scan", "--command", "npx", "$HOME/x", "${NOPE}").Arguments);

    [Fact]
    public void ACommandWithNothingAfterIt_IsAnError() =>
        Assert.Contains("needs the server's command line", Error("scan", "--command"), StringComparison.Ordinal);

    [Fact]
    public void AUrlTarget_IsStreamableHttpUnlessSseIsAsked()
    {
        var http = Target("scan", "--url", "https://mcp.example.com/mcp", "--header", "Authorization: Bearer abc");

        Assert.Equal(UpstreamTransport.Http, http.Transport);
        Assert.Equal(new Uri("https://mcp.example.com/mcp"), http.Url);
        Assert.Equal("Bearer abc", http.Headers!["Authorization"]);

        Assert.Equal(UpstreamTransport.Sse, Target("scan", "--url", "https://mcp.example.com/sse", "--sse").Transport);
    }

    [Theory]
    [InlineData("Authorization Bearer abc")]
    [InlineData(": abc")]
    public void AHeaderWithoutANameAndColon_IsAnError_WithoutEchoingIt(string header)
    {
        var message = Error("scan", "--url", "https://mcp.example.com/mcp", "--header", header);

        Assert.Contains("'Name: value'", message, StringComparison.Ordinal);
        Assert.DoesNotContain("abc", message, StringComparison.Ordinal);
    }

    [Fact]
    public void ContradictoryTargets_AreErrors()
    {
        Assert.Contains("not both", Error("scan", "--url", "https://x.example/mcp", "--command", "npx"), StringComparison.Ordinal);
        Assert.Contains("one or the other", Error("scan", "--servers", "s.yaml", "--command", "npx"), StringComparison.Ordinal);
        Assert.Contains("one or the other", Error("scan", "--servers", "s.yaml", "--url", "https://x.example/mcp"), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--sse")]
    [InlineData("--header", "A: b")]
    public void RemoteOnlyFlags_NeedAUrl(params string[] flags) =>
        Assert.Contains("only apply to a --url target", Error(["scan", .. flags]), StringComparison.Ordinal);

    [Fact]
    public void ACommandTarget_GoesThroughTheServersFileRules()
    {
        // An unpinned package runner is warned about here as it is in a file.
        var document = ScanOptions.Parse(["scan", "--command", "npx", "-y", "some-server"]).TargetDocument!;
        var result = ServersLoader.Parse(document, FakeHost.At("work"), new FakeHost().Build());

        Assert.Contains(result.Warnings, warning => warning.Contains("without a pinned version", StringComparison.Ordinal));
    }
}
