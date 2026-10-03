using System.Reflection;
using McpGuardrails.Core.Hosting;

namespace McpGuardrails.Core.Tests.Hosting;

public sealed class ProxyVersionTests
{
    [Theory]
    [InlineData("1.2.3", "1.2.3")]
    [InlineData("1.2.3+0123456789abcdef", "1.2.3")]
    [InlineData("1.2.3-rc.1+build.5", "1.2.3-rc.1")]
    [InlineData(null, ProxyVersion.Unknown)]
    [InlineData("", ProxyVersion.Unknown)]
    [InlineData("+abcdef", ProxyVersion.Unknown)]
    public void Normalize_KeepsTheVersionAndDropsBuildMetadata(string? informational, string expected) =>
        Assert.Equal(expected, ProxyVersion.Normalize(informational));

    [Fact]
    public void Normalize_FallsBackWhenTheAttributeIsMissing()
    {
        Assert.Equal(ProxyVersion.Unknown, ProxyVersion.Normalize((AssemblyInformationalVersionAttribute?)null));
        Assert.Equal("2.0.0", ProxyVersion.Normalize(new AssemblyInformationalVersionAttribute("2.0.0+abc")));
    }

    [Fact]
    public void Of_ReadsTheStampedVersionWithoutTheCommit()
    {
        // The SDK stamps every assembly with an informational version, so this
        // exercises the real attribute lookup rather than a stub.
        var version = ProxyVersion.Of(typeof(ProxyVersion).Assembly);

        Assert.NotEqual(ProxyVersion.Unknown, version);
        Assert.DoesNotContain('+', version);
    }

    [Fact]
    public void Of_RejectsNull() =>
        Assert.Throws<ArgumentNullException>(() => ProxyVersion.Of(null!));
}
