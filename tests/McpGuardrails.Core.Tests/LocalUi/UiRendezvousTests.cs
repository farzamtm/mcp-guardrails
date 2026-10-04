using McpGuardrails.Core.LocalUi;

namespace McpGuardrails.Core.Tests.LocalUi;

public sealed class UiRendezvousTests
{
    private static readonly byte[] _secret = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();

    [Fact]
    public void SerializeThenParse_RoundTrips()
    {
        var endpoint = new UiEndpoint(new Uri("http://127.0.0.1:53817/"), _secret);
        var text = UiRendezvous.Serialize(endpoint, processId: 4242, startedAt: DateTimeOffset.UtcNow);

        var parsed = UiRendezvous.Parse(text);

        Assert.NotNull(parsed);
        Assert.Equal(endpoint.Url, parsed!.Url);
        Assert.Equal(endpoint.Secret, parsed.Secret);
        Assert.Equal(new Uri("http://127.0.0.1:53817/api/approvals"), parsed.ApprovalsUrl);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not json")]
    [InlineData("""{"version": 2, "url": "http://127.0.0.1:1/", "secret": "AAAAAAAAAAAAAAAAAAAAAA=="}""")]
    public void AFileThatCannotBeTrusted_ParsesToNull(string? text)
    {
        Assert.Null(UiRendezvous.Parse(text));
    }

    [Theory]
    [InlineData("https://127.0.0.1:1/")] // not plain http
    [InlineData("http://example.com/")] // not loopback
    [InlineData("http://localhost/")] // a name, not a literal loopback address
    [InlineData("http://user@127.0.0.1:1/")] // carries credentials
    public void AUrlThatIsNotPlainLoopbackHttp_IsRefused(string url)
    {
        var text = $$"""{"version": 1, "url": "{{url}}", "secret": "AAAAAAAAAAAAAAAAAAAAAA=="}""";

        Assert.Null(UiRendezvous.Parse(text));
    }

    [Theory]
    [InlineData("not base64!!!")]
    [InlineData("AAAAAAAAAAAAAA==")] // decodes to 10 bytes, short of the 16-byte floor
    public void ASecretThatIsNotAUsableKey_IsRefused(string secret)
    {
        var text = $$"""{"version": 1, "url": "http://127.0.0.1:1/", "secret": "{{secret}}"}""";

        Assert.Null(UiRendezvous.Parse(text));
    }

    [Theory]
    [InlineData("http://127.0.0.1:53817/")]
    [InlineData("http://[::1]:53817/")]
    public void LoopbackAddresses_AreAccepted(string url)
    {
        Assert.True(UiRendezvous.IsLoopbackHttp(new Uri(url)));
    }
}
