using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Tests.Upstream;

public sealed class UpstreamServerConfigTests
{
    private static UpstreamServerConfig Valid(string name) => new()
    {
        Name = name,
        Command = "npx",
    };

    [Theory]
    [InlineData("fs")]
    [InlineData("commercetools")]
    [InlineData("my-server-2")]
    public void Validate_AcceptsLettersDigitsAndHyphens(string name)
    {
        Valid(name).Validate(); // must not throw
    }

    [Theory]
    [InlineData("my_server")]   // underscore would make "__" splitting ambiguous
    [InlineData("fs__x")]
    [InlineData("has space")]
    [InlineData("dot.name")]
    public void Validate_RejectsNamesThatBreakNamespacing(string name)
    {
        Assert.Throws<ArgumentException>(() => Valid(name).Validate());
    }

    [Fact]
    public void Validate_RejectsBlankCommand()
    {
        var config = new UpstreamServerConfig { Name = "fs", Command = "  " };

        Assert.Throws<ArgumentException>(config.Validate);
    }

    [Fact]
    public void Validate_RejectsOAuthOnAStdioServer()
    {
        var config = Valid("fs") with { OAuth = new UpstreamOAuthSettings([]) };

        Assert.Contains("stdio but has OAuth settings", Assert.Throws<ArgumentException>(config.Validate).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_AcceptsOAuthOnARemoteServer()
    {
        new UpstreamServerConfig
        {
            Name = "linear",
            Transport = UpstreamTransport.Http,
            Url = new Uri("https://mcp.linear.app/mcp"),
            OAuth = new UpstreamOAuthSettings(["read"]),
        }.Validate(); // must not throw
    }

    [Fact]
    public void Validate_RejectsContainerIsolationOnARemoteServer()
    {
        var config = new UpstreamServerConfig
        {
            Name = "docs",
            Transport = UpstreamTransport.Http,
            Url = new Uri("https://mcp.example.com/mcp"),
            Isolation = new ContainerIsolation { Runtime = ContainerRuntime.Docker, Image = "img" },
        };

        Assert.Contains("remote server but has container isolation", Assert.Throws<ArgumentException>(config.Validate).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Reach_SaysWhatAServerCanTouch()
    {
        Assert.StartsWith("everything you can: it runs directly on the host", Valid("fs").Reach(), StringComparison.Ordinal);

        var isolated = Valid("fs") with
        {
            Isolation = new ContainerIsolation { Runtime = ContainerRuntime.Docker, Image = "img" },
        };
        Assert.Equal(isolated.Isolation!.Describe(), isolated.Reach());

        Assert.Null(new UpstreamServerConfig
        {
            Name = "docs",
            Transport = UpstreamTransport.Http,
            Url = new Uri("https://mcp.example.com/mcp"),
        }.Reach());
    }

    [Fact]
    public void HostEnvironment_ReportsNoUser_UnlessTheHostSaysOtherwise()
    {
        var host = new HostEnvironment
        {
            GetVariable = _ => null,
            VariableNames = () => [],
            FileExists = _ => false,
            DirectoryExists = _ => false,
            ReadAllText = _ => string.Empty,
            GetUnixFileMode = _ => null,
            HomeDirectory = "/home/user",
        };

        Assert.Null(host.UserAndGroup());
    }
}
