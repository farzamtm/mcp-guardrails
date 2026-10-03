using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Policy;

/// <summary>
/// The shared rules for every URL the proxy sends requests to. The callers'
/// own tests cover their wiring; these pin the rules themselves, including the
/// combinations no caller uses today.
/// </summary>
public sealed class OutboundUrlTests
{
    private const string _setting = "example.url";
    private const string _reason = "It carries a secret";
    private const string _hint = "use 'secret_env'";

    private static Uri Validate(string url, bool allowLoopbackHttp, string? optIn = null) =>
        OutboundUrl.Validate(url, _setting, _reason, _hint, allowLoopbackHttp, optIn);

    private static string Rejects(string url, bool allowLoopbackHttp, string? optIn = null) =>
        Assert.Throws<PolicyException>(() => Validate(url, allowLoopbackHttp, optIn)).Message;

    [Theory]
    [InlineData("https://example.test/path", false)]
    [InlineData("https://example.test/path", true)]
    [InlineData("http://localhost:8080/", true)]
    [InlineData("http://127.0.0.1:8080/", true)]
    [InlineData("http://[::1]:8080/", true)]
    public void SafeUrls_AreReturnedParsed(string url, bool allowLoopbackHttp)
    {
        Assert.Equal(new Uri(url), Validate(url, allowLoopbackHttp));
    }

    [Fact]
    public void ARelativeUrl_IsRejectedWithoutEchoingIt()
    {
        var message = Rejects("not a url hunter2", allowLoopbackHttp: true);

        Assert.Equal("'example.url' is not an absolute URL.", message);
    }

    [Theory]
    [InlineData("https://user:hunter2@example.test/")]
    [InlineData("https://hunter2@example.test/")]
    [InlineData("http://user:hunter2@localhost/")]
    public void Credentials_AreRejectedEvenWhereTheSchemeIsFine(string url)
    {
        var message = Rejects(url, allowLoopbackHttp: true);

        Assert.Contains("'example.url' contains credentials", message, StringComparison.Ordinal);
        Assert.Contains(_hint, message, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2", message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnotherScheme_IsRejected()
    {
        Assert.Equal(
            "'example.url' uses 'ftp'. Use https.",
            Rejects("ftp://localhost/", allowLoopbackHttp: true));
    }

    [Fact]
    public void PlainHttpNotAllowed_NamesTheOptInWhenThereIsOne()
    {
        var message = Rejects("http://localhost/", allowLoopbackHttp: false, optIn: "allow_it");

        Assert.Contains(_reason, message, StringComparison.Ordinal);
        Assert.Contains("set 'allow_it: true'", message, StringComparison.Ordinal);
    }

    [Fact]
    public void PlainHttpNotAllowed_WithNoOptIn_JustSaysHttps()
    {
        Assert.Equal(
            "'example.url' uses plain http. It carries a secret, so use https.",
            Rejects("http://localhost/", allowLoopbackHttp: false));
    }

    [Fact]
    public void PlainHttpOffLoopback_IsRejectedEvenWhenAllowed()
    {
        var message = Rejects("http://example.test/", allowLoopbackHttp: true);

        Assert.Contains("'example.test'", message, StringComparison.Ordinal);
        Assert.Contains("plain http is accepted only for loopback", message, StringComparison.Ordinal);
    }

    [Fact]
    public void PlainHttpOffLoopback_BlamesTheOptInWhenThereIsOne()
    {
        var message = Rejects("http://example.test/", allowLoopbackHttp: true, optIn: "allow_it");

        Assert.Contains("'allow_it' only permits loopback", message, StringComparison.Ordinal);
    }
}
