using McpGuardrails.Core.UpstreamAuth;

namespace McpGuardrails.Core.Tests.UpstreamAuth;

public sealed class LoopbackCallbackTests
{
    [Fact]
    public void ACallback_YieldsCodeStateAndIssuer()
    {
        var result = LoopbackCallback.Parse(
            "GET /callback?code=abc%2B1&state=s+t&iss=https%3A%2F%2Fauth.example.com HTTP/1.1");

        Assert.Equal("abc+1", result.Code);
        Assert.Equal("s t", result.State);
        Assert.Equal("https://auth.example.com", result.Iss);
    }

    [Fact]
    public void StateAndIssuer_AreOptionalHere_TheSdkChecksThem()
    {
        var result = LoopbackCallback.Parse("GET /callback?code=abc HTTP/1.1");

        Assert.Null(result.State);
        Assert.Null(result.Iss);
    }

    [Fact]
    public void ARepeatedParameter_KeepsTheFirst()
    {
        Assert.Equal("first", LoopbackCallback.Parse("GET /callback?code=first&code=second HTTP/1.1").Code);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("GET /callback?code=a")]
    [InlineData("POST /callback?code=a HTTP/1.1")]
    [InlineData("GET /other?code=a HTTP/1.1")]
    [InlineData("GET http://[bad/callback HTTP/1.1")]
    public void SomethingElse_IsNotACallback(string? line)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => LoopbackCallback.Parse(line));
        Assert.Contains("not a login callback", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnErrorFromTheAuthorizationServer_IsReported()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => LoopbackCallback.Parse("GET /callback?error=access_denied&error_description=User%20said%20no%0A HTTP/1.1"));

        Assert.Contains("refused the login (access_denied: User said no)", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnErrorWithoutADescription_IsReported()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => LoopbackCallback.Parse($"GET /callback?error={new string('x', 300)} HTTP/1.1"));

        Assert.Contains($"({new string('x', 200)}).", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("GET /callback?state=s HTTP/1.1")]
    [InlineData("GET /callback?code=&state=s HTTP/1.1")]
    [InlineData("GET /callback?code HTTP/1.1")]
    public void NoCode_IsReported(string line)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => LoopbackCallback.Parse(line));
        Assert.Contains("no authorization code", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ThePage_SaysWhatHappened()
    {
        Assert.Contains("Logged in", LoopbackCallback.Page(succeeded: true), StringComparison.Ordinal);
        Assert.Contains("did not complete", LoopbackCallback.Page(succeeded: false), StringComparison.Ordinal);
    }
}
