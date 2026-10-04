using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Scanners;
using McpGuardrails.Core.Tests.Scanners;
using McpGuardrails.Core.Upstream;
using ModelContextProtocol.Client;

namespace McpGuardrails.Core.Tests.Upstream;

public sealed class PackageRunnersTests
{
    [Theory]
    [InlineData("npx", new[] { "-y", "some-server" }, "some-server")]
    [InlineData("npx", new[] { "-y", "@scope/server" }, "@scope/server")]
    [InlineData("npx", new[] { "some-server@latest" }, "some-server@latest")]
    [InlineData("npx", new[] { "some-server@^1.2" }, "some-server@^1.2")]
    [InlineData("npx", new[] { "some-server@" }, "some-server@")]
    [InlineData("/usr/local/bin/npx", new[] { "--package", "tool", "run" }, "tool")]
    [InlineData(@"C:\Program Files\nodejs\npx.cmd", new[] { "--package=tool" }, "tool")]
    [InlineData("bunx", new[] { "-p", "tool" }, "tool")]
    [InlineData("uvx", new[] { "mcp-server-fetch" }, "mcp-server-fetch")]
    [InlineData("uvx", new[] { "--from", "pkg==", "cmd" }, "pkg==")]
    [InlineData("uvx", new[] { "==1.0" }, "==1.0")]
    public void FindUnpinned_ReportsAPackageThatCanMove(string command, string[] arguments, string expected) =>
        Assert.Equal(expected, PackageRunners.FindUnpinned(command, arguments));

    [Theory]
    [InlineData("npx", new[] { "-y", "some-server@1.2.3" })]
    [InlineData("npx", new[] { "-y", "@scope/server@2026.8.31" })]
    [InlineData("npx", new[] { "-y" })]                    // nothing to fetch
    [InlineData("npx", new[] { "--package" })]             // option without its value
    [InlineData("uvx", new[] { "mcp-server-fetch==2025.4.7" })]
    [InlineData("uvx", new[] { "mcp-server-fetch@2025.4.7" })]
    [InlineData("uvx", new[] { "--from", "pkg==1.0", "cmd" })]
    [InlineData("python3", new[] { "server.py" })]       // not a package runner
    [InlineData("docker", new[] { "run", "image" })]
    public void FindUnpinned_IgnoresPinnedPackagesAndOtherCommands(string command, string[] arguments) =>
        Assert.Null(PackageRunners.FindUnpinned(command, arguments));

    [Fact]
    public void FindUnpinned_RejectsNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => PackageRunners.FindUnpinned(null!, []));
        Assert.Throws<ArgumentNullException>(() => PackageRunners.FindUnpinned("npx", null!));
    }
}

public sealed class EnvironmentIsolationTests
{
    [Theory]
    [InlineData("PATH", true)]
    [InlineData("Path", true)]          // Windows spelling
    [InlineData("SystemRoot", true)]
    [InlineData("NODE_ENV", true)]      // via the glob below
    [InlineData("ANTHROPIC_API_KEY", false)]
    [InlineData("node_env", false)]     // globs are case-sensitive
    public void IsPassed_ChecksTheAllowlistAndPassthrough(string name, bool expected) =>
        Assert.Equal(expected, EnvironmentIsolation.IsPassed(name, ["NODE_*"]));

    [Fact]
    public void ChildEnvironment_SkipsAVariableThatVanished()
    {
        // Listed by name but gone by the time it is read: not passed as null.
        var host = new FakeHost().Build();
        var vanishing = new HostEnvironment
        {
            GetVariable = name => name == "HOME" ? null : host.GetVariable(name),
            VariableNames = host.VariableNames,
            FileExists = host.FileExists,
            DirectoryExists = host.DirectoryExists,
            ReadAllText = host.ReadAllText,
            GetUnixFileMode = host.GetUnixFileMode,
            HomeDirectory = host.HomeDirectory,
        };

        var environment = EnvironmentIsolation.ChildEnvironment(vanishing, [], new Dictionary<string, string?>());

        Assert.False(environment.ContainsKey("HOME"));
        Assert.True(environment.ContainsKey("PATH"));
    }

    [Fact]
    public void RejectsNullArguments()
    {
        var host = new FakeHost().Build();
        var own = new Dictionary<string, string?>();

        Assert.Throws<ArgumentNullException>(() => EnvironmentIsolation.ChildEnvironment(null!, [], own));
        Assert.Throws<ArgumentNullException>(() => EnvironmentIsolation.ChildEnvironment(host, null!, own));
        Assert.Throws<ArgumentNullException>(() => EnvironmentIsolation.ChildEnvironment(host, [], null!));
        Assert.Throws<ArgumentNullException>(() => EnvironmentIsolation.WouldWithhold(null!, [], own));
        Assert.Throws<ArgumentNullException>(() => EnvironmentIsolation.WouldWithhold(host, null!, own));
        Assert.Throws<ArgumentNullException>(() => EnvironmentIsolation.WouldWithhold(host, [], null!));
    }
}

public sealed class UpstreamAuditTests
{
    [Theory]
    [InlineData(UpstreamTransport.Stdio, "stdio")]
    [InlineData(UpstreamTransport.Http, "http")]
    [InlineData(UpstreamTransport.Sse, "sse")]
    public void ToWireName_SpellsEveryTransport(UpstreamTransport transport, string expected) =>
        Assert.Equal(expected, transport.ToWireName());

    [Fact]
    public void ToWireName_RefusesAnUndefinedValue() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => ((UpstreamTransport)42).ToWireName());

    [Fact]
    public async Task Connected_RecordsTheServerItsTemplateAndToolCount()
    {
        await using var server = InMemoryMcpServer.Start("fixture");
        await using var client = await McpClient.CreateAsync(server.TransportFactory(null!, null!));

        var config = new UpstreamServerConfig
        {
            Name = "docs",
            Transport = UpstreamTransport.Http,
            Url = new Uri("https://x.example"),
            DisplayTemplate = "https://${HOST}/mcp",
        };
        var record = UpstreamAudit.Connected(new UpstreamConnection("docs", client, []) { Config = config }, DateTimeOffset.UnixEpoch);

        Assert.Equal(UpstreamAudit.ConnectedEvent, record.Event);
        Assert.Equal("docs", record.Server);
        Assert.Equal("http", record.Transport);
        Assert.Equal(0, record.ToolCount);
        Assert.Equal("https://${HOST}/mcp", record.Identity);
        Assert.Null(record.Tool);

        var bare = UpstreamAudit.Connected(new UpstreamConnection("fs", client, []), DateTimeOffset.UnixEpoch);
        Assert.Equal("stdio", bare.Transport);
        Assert.Null(bare.Identity);
    }

    [Fact]
    public void Connected_RejectsNull() =>
        Assert.Throws<ArgumentNullException>(() => UpstreamAudit.Connected(null!, DateTimeOffset.UnixEpoch));
}

public sealed class UpstreamServerConfigTransportTests
{
    [Fact]
    public void Validate_AcceptsARemoteServerWithAUrl() =>
        new UpstreamServerConfig { Name = "docs", Transport = UpstreamTransport.Sse, Url = new Uri("https://x.example") }.Validate();

    [Theory]
    [InlineData(UpstreamTransport.Stdio, "npx", true, "has a URL")]
    [InlineData(UpstreamTransport.Http, null, false, "has no URL")]
    [InlineData(UpstreamTransport.Http, "npx", true, "has a command")]
    [InlineData((UpstreamTransport)42, null, true, "unknown transport")]
    public void Validate_RefusesAMixedUpConfig(UpstreamTransport transport, string? command, bool withUrl, string expected)
    {
        var config = new UpstreamServerConfig
        {
            Name = "a",
            Transport = transport,
            Command = command,
            Url = withUrl ? new Uri("https://x.example") : null,
        };

        Assert.Contains(expected, Assert.Throws<ArgumentException>(config.Validate).Message, StringComparison.Ordinal);
    }
}

public sealed class SecretScanTests
{
    [Fact]
    public void Scan_JudgesByContentAndByKey()
    {
        Assert.False(SecretScanner.Scan(SecretSamples.GitHubToken, null, includePii: false).IsClean);
        Assert.False(SecretScanner.Scan("hunter2", "password", includePii: false).IsClean);
        Assert.True(SecretScanner.Scan("hunter2", "path", includePii: false).IsClean);
        Assert.Throws<ArgumentNullException>(() => SecretScanner.Scan(null!, null, includePii: false));
    }
}

public sealed class PolicyServerCrossCheckTests
{
    [Fact]
    public void RulesMatchingNoServer_NamesRulesScopedToAbsentServers()
    {
        var policy = new PolicyDocument
        {
            Rules =
            [
                new PolicyRule { Name = "any", Match = new PolicyMatch { Tool = "x" } },
                new PolicyRule { Name = "github", Match = new PolicyMatch { Server = "github" } },
                new PolicyRule { Name = "glob", Match = new PolicyMatch { Server = "f*" } },
                new PolicyRule { Name = "catch-all" },
            ],
        };

        Assert.Equal(["github"], policy.RulesMatchingNoServer(["fs"]));
        Assert.Throws<ArgumentNullException>(() => policy.RulesMatchingNoServer(null!));
    }
}
