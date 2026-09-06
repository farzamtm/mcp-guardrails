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
}
