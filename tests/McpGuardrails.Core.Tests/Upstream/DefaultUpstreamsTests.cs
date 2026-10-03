using McpGuardrails.Core.Upstream;
using Microsoft.Extensions.Logging.Abstractions;

namespace McpGuardrails.Core.Tests.Upstream;

public sealed class DefaultUpstreamsTests
{
    [Fact]
    public void Create_ProducesAValidFilesystemServerConfig()
    {
        var configs = DefaultUpstreams.Create("/tmp/sandbox");

        var config = Assert.Single(configs);

        // Must survive its own validation, or startup would fail on the defaults.
        config.Validate();

        Assert.Equal("fs", config.Name);
        Assert.Equal("npx", config.Command);
    }

    [Fact]
    public void Create_PinsTheFilesystemServerToAnExactVersion()
    {
        // A bare package name lets npx run whatever npm publishes next. The literal
        // here is deliberate: a bump should be a visible two-line change, not a
        // constant edited in one place and silently echoed back by the test.
        var arguments = Assert.Single(DefaultUpstreams.Create("/tmp/sandbox")).Arguments;

        Assert.Contains("@modelcontextprotocol/server-filesystem@2026.8.31", arguments);
        Assert.DoesNotContain("@modelcontextprotocol/server-filesystem", arguments);
    }

    [Fact]
    public void Create_SandboxesTheServerToTheGivenPath()
    {
        // The sandbox path is the only thing standing between the agent and the
        // whole filesystem, so it must actually reach the server's argv.
        var configs = DefaultUpstreams.Create("/tmp/only-here");

        Assert.Contains("/tmp/only-here", Assert.Single(configs).Arguments);
    }

    [Fact]
    public void Create_NamesAreUniqueAndNamespaceable()
    {
        var configs = DefaultUpstreams.Create("/tmp/sandbox");

        var names = configs.Select(c => c.Name).ToList();
        Assert.Equal(names.Count, names.Distinct(StringComparer.Ordinal).Count());

        foreach (var config in configs)
        {
            Assert.True(
                ToolNamespacer.TrySplit(
                    ToolNamespacer.Qualify(config.Name, "tool"), out var server, out _));
            Assert.Equal(config.Name, server);
        }
    }
}

public sealed class StdioTransportFactoryTests
{
    [Fact]
    public void CreateStdioTransport_MapsConfigOntoTheTransport()
    {
        var config = new UpstreamServerConfig
        {
            Name = "fs",
            Command = "npx",
            Arguments = ["-y", "server-filesystem", "/tmp"],
            EnvironmentVariables = new Dictionary<string, string?> { ["TOKEN"] = "secret" },
        };

        var transport = UpstreamRegistry.CreateStdioTransport(
            config, NullLoggerFactory.Instance);

        Assert.NotNull(transport);
        Assert.Equal("fs", transport.Name);
    }

    [Fact]
    public void CreateStdioTransport_HandlesAbsentEnvironmentVariables()
    {
        // EnvironmentVariables is nullable; the null-conditional ToDictionary must
        // not blow up when a config omits it (which most do).
        var config = new UpstreamServerConfig { Name = "fs", Command = "npx" };

        var transport = UpstreamRegistry.CreateStdioTransport(
            config, NullLoggerFactory.Instance);

        Assert.NotNull(transport);
    }
}
