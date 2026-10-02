using System.Net;
using McpGuardrails.Core.Hosting;

namespace McpGuardrails.Core.Tests.Hosting;

public sealed class ServeOptionsTests
{
    private const string _token = "0123456789abcdef0123";

    private static ServeOptions Parse(string commandLine, string? token = null) =>
        ServeOptions.Parse(
            commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            token);

    private static string Rejected(string commandLine, string? token = null) =>
        Assert.Throws<ServeOptionsException>(() => Parse(commandLine, token)).Message;

    // ----------------------------------------------------------------- stdio

    [Theory]
    [InlineData("")]
    [InlineData("--explain list-upstream")]
    [InlineData("--transport stdio")]
    public void WithoutAnHttpTransport_ItIsStdio(string commandLine)
    {
        Assert.Same(ServeOptions.Default, Parse(commandLine));
        Assert.Equal(Transport.Stdio, ServeOptions.Default.Transport);
    }

    [Fact]
    public void Stdio_IgnoresATokenLeftInTheEnvironment()
    {
        // The variable may be exported for the whole shell; stdio has no network.
        var options = Parse("", token: "short");

        Assert.Null(options.BearerToken);
        Assert.False(options.RequiresToken);
    }

    [Theory]
    [InlineData("--port 8080")]
    [InlineData("--bind 127.0.0.1")]
    [InlineData("--transport stdio --port 8080")]
    public void NetworkFlags_WithStdio_AreAnError(string commandLine)
    {
        Assert.Contains("only apply to '--transport http'", Rejected(commandLine), StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ http

    [Fact]
    public void Http_DefaultsToLoopbackOnTheDefaultPort_WithoutAToken()
    {
        var options = Parse("--transport http");

        Assert.Equal(Transport.Http, options.Transport);
        Assert.Equal(IPAddress.Loopback, options.BindAddress);
        Assert.Equal(ServeOptions.DefaultPort, options.Port);
        Assert.False(options.RequiresToken);
    }

    [Theory]
    [InlineData("0", 0)]
    [InlineData("8080", 8080)]
    [InlineData("65535", 65535)]
    public void Http_TakesAnyValidPort_IncludingZeroForAnEphemeralOne(string port, int expected)
    {
        Assert.Equal(expected, Parse($"--transport http --port {port}").Port);
    }

    [Theory]
    [InlineData("65536")]
    [InlineData("-1")]
    [InlineData("80a")]
    [InlineData("+80")]
    public void Http_RejectsAPortThatIsNotOne(string port)
    {
        Assert.Contains("is not a port number", Rejected($"--transport http --port {port}"), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("127.0.0.2")]
    public void Http_BindsAnyLoopbackAddress_WithoutAToken(string address)
    {
        Assert.Equal(IPAddress.Parse(address), Parse($"--transport http --bind {address}").BindAddress);
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("192.168.1.10")]
    public void Http_RefusesANonLoopbackBind_WithoutAToken(string address)
    {
        // Nothing else authenticates the caller, so this is not offered at all.
        Assert.Contains("without authentication", Rejected($"--transport http --bind {address}"), StringComparison.Ordinal);
    }

    [Fact]
    public void Http_AllowsANonLoopbackBind_WithAToken()
    {
        var options = Parse("--transport http --bind 0.0.0.0", token: _token);

        Assert.Equal(IPAddress.Any, options.BindAddress);
        Assert.True(options.RequiresToken);
        Assert.Equal(_token, options.BearerToken);
    }

    [Fact]
    public void Http_TrimsTheToken()
    {
        // A trailing newline from `$(cat token-file)` must not lock everyone out.
        Assert.Equal(_token, Parse("--transport http", token: $" {_token}\n").BearerToken);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("tooshort")]
    [InlineData("  fifteen-chars  ")]
    public void Http_RejectsATokenTooShortToBeOne(string token)
    {
        // Set-but-useless is a mistake, not "no token": failing open here would
        // serve an unauthenticated endpoint to someone who asked for auth.
        Assert.Contains("at least", Rejected("--transport http", token), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("example.com")]
    public void Http_RejectsAHostName(string bind)
    {
        Assert.Contains("is not an IP address", Rejected($"--transport http --bind {bind}"), StringComparison.Ordinal);
    }

    // --------------------------------------------------------------- syntax

    [Fact]
    public void AnUnknownTransport_IsAnError()
    {
        Assert.Contains("Unknown transport 'sse'", Rejected("--transport sse"), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--transport")]
    [InlineData("--transport http --port")]
    [InlineData("--transport http --bind --port 1")]
    public void AFlagWithoutAValue_IsAnError(string commandLine)
    {
        Assert.Contains("needs a value", Rejected(commandLine), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--transport http --transport stdio")]
    [InlineData("--transport http --port 1 --port 2")]
    [InlineData("--transport http --bind ::1 --bind 127.0.0.1")]
    public void ARepeatedFlag_IsAnError_RatherThanLastOneWins(string commandLine)
    {
        Assert.Contains("more than once", Rejected(commandLine), StringComparison.Ordinal);
    }

    [Fact]
    public void NullArguments_Throw()
    {
        Assert.Throws<ArgumentNullException>(() => ServeOptions.Parse(null!, null));
    }
}
