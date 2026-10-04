using McpGuardrails.Core.Upstream;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Authentication;
using ModelContextProtocol.Client;

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
        Assert.Equal(
            "npx -y @modelcontextprotocol/server-filesystem@2026.8.31 /tmp/sandbox",
            config.DisplayTemplate);
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

public sealed class TransportFactoryTests
{
    [Fact]
    public void StdioOptions_MapsEveryFieldOntoTheLaunchOptions()
    {
        var config = new UpstreamServerConfig
        {
            Name = "fs",
            Command = "npx",
            Arguments = ["-y", "server-filesystem", "/tmp"],
            EnvironmentVariables = new Dictionary<string, string?> { ["TOKEN"] = "secret" },
            InheritEnvironment = false,
            WorkingDirectory = "/srv",
            ShutdownTimeout = TimeSpan.FromSeconds(9),
        };

        var options = UpstreamRegistry.StdioOptions(config);

        Assert.Equal("fs", options.Name);
        Assert.Equal("npx", options.Command);
        Assert.Equal(["-y", "server-filesystem", "/tmp"], options.Arguments);
        Assert.Equal("secret", options.EnvironmentVariables!["TOKEN"]);
        // The switch that keeps the proxy's own secrets out of the child: a
        // mapping that dropped it would quietly undo env_isolation.
        Assert.False(options.InheritEnvironmentVariables);
        Assert.Equal("/srv", options.WorkingDirectory);
        Assert.Equal(TimeSpan.FromSeconds(9), options.ShutdownTimeout);
    }

    [Fact]
    public void StdioOptions_KeepsTheSdkDefaultsWhenTheConfigIsBare()
    {
        // EnvironmentVariables is nullable; the null-conditional ToDictionary must
        // not blow up when a config omits it (which most do).
        var options = UpstreamRegistry.StdioOptions(new UpstreamServerConfig { Name = "fs", Command = "npx" });

        Assert.Null(options.EnvironmentVariables);
        Assert.True(options.InheritEnvironmentVariables);
        Assert.Equal(new StdioClientTransportOptions { Command = "x" }.ShutdownTimeout, options.ShutdownTimeout);
    }

    [Theory]
    [InlineData(UpstreamTransport.Http, HttpTransportMode.StreamableHttp)]
    [InlineData(UpstreamTransport.Sse, HttpTransportMode.Sse)]
    public void HttpOptions_NamesTheTransportModeExplicitly(UpstreamTransport transport, HttpTransportMode expected)
    {
        // Never AutoDetect: its silent fallback to SSE is a downgrade nobody chose.
        var options = UpstreamRegistry.HttpOptions(new UpstreamServerConfig
        {
            Name = "docs",
            Transport = transport,
            Url = new Uri("https://mcp.example.com/mcp"),
            Headers = new Dictionary<string, string> { ["Authorization"] = "Bearer t" },
        });

        Assert.Equal(expected, options.TransportMode);
        Assert.Equal(new Uri("https://mcp.example.com/mcp"), options.Endpoint);
        Assert.Equal("Bearer t", options.AdditionalHeaders!["authorization"]);
    }

    [Fact]
    public void HttpOptions_CarryTheOAuthSettings()
    {
        var config = new UpstreamServerConfig
        {
            Name = "linear",
            Transport = UpstreamTransport.Http,
            Url = new Uri("https://mcp.linear.app/mcp"),
        };
        var oauth = new ClientOAuthOptions { RedirectUri = new Uri("http://127.0.0.1/callback") };

        Assert.Same(oauth, UpstreamRegistry.HttpOptions(config, oauth).OAuth);
        Assert.Null(UpstreamRegistry.HttpOptions(config).OAuth);
    }

    [Fact]
    public void HttpOptions_AllowsNoHeaders()
    {
        var options = UpstreamRegistry.HttpOptions(new UpstreamServerConfig
        {
            Name = "docs",
            Transport = UpstreamTransport.Http,
            Url = new Uri("https://mcp.example.com/mcp"),
        });

        Assert.Null(options.AdditionalHeaders);
    }

    [Fact]
    public async Task CreateTransport_PicksTheTransportForTheConfig()
    {
        var stdio = UpstreamRegistry.CreateTransport(
            new UpstreamServerConfig { Name = "fs", Command = "npx" }, NullLoggerFactory.Instance);
        await using var http = (HttpClientTransport)UpstreamRegistry.CreateTransport(
            new UpstreamServerConfig
            {
                Name = "docs",
                Transport = UpstreamTransport.Http,
                Url = new Uri("https://mcp.example.com/mcp"),
            },
            NullLoggerFactory.Instance);

        Assert.IsType<StdioClientTransport>(stdio);
        Assert.Equal("docs", http.Name);
    }
}
