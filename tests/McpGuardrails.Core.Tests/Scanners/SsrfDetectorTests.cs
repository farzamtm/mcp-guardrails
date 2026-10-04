using McpGuardrails.Core.Scanners;

namespace McpGuardrails.Core.Tests.Scanners;

/// <summary>
/// The SSRF detector against a corpus of internal addresses, the encodings
/// attackers use to disguise them, and ordinary URLs that must stay quiet.
/// </summary>
public sealed class SsrfDetectorTests
{
    [Theory]
    // Loopback and the unspecified address.
    [InlineData("http://127.0.0.1/")]
    [InlineData("http://127.8.9.10:8080/admin")]
    [InlineData("http://localhost:3000")]
    [InlineData("HTTP://LOCALHOST")]
    [InlineData("http://localhost./")]
    [InlineData("http://app.localhost/")]
    [InlineData("http://0.0.0.0:9000")]
    [InlineData("http://0/")]
    // RFC 1918, link-local and metadata, carrier-grade NAT.
    [InlineData("http://10.0.0.5/")]
    [InlineData("https://172.16.0.1/")]
    [InlineData("https://172.31.255.255/")]
    [InlineData("http://192.168.1.1/")]
    [InlineData("http://169.254.169.254/latest/meta-data/iam/security-credentials/")]
    [InlineData("http://100.64.0.1/")]
    [InlineData("http://100.127.255.255/")]
    [InlineData("http://metadata.google.internal/computeMetadata/v1/")]
    // Encoded IPv4: decimal, octal, hex, short forms, a trailing dot.
    [InlineData("http://2130706433/")]
    [InlineData("http://017700000001/")]
    [InlineData("http://0x7f000001/")]
    [InlineData("http://0X7F.0.0.1/")]
    [InlineData("http://0177.0.0.1/")]
    [InlineData("http://127.1/")]
    [InlineData("http://10.1.257/")]
    [InlineData("http://169.254.43518/")]
    [InlineData("http://127.0.0.1./")]
    // Percent-encoded and full-width dots in the host.
    [InlineData("http://127%2e0%2e0%2e1/")]
    [InlineData("http://127。0。0。1/")]
    [InlineData("http://127．0．0．1/")]
    [InlineData("http://127｡0｡0｡1/")]
    // IPv6: loopback, unspecified, ULA, link-local, site-local, embedded IPv4.
    [InlineData("http://[::1]/")]
    [InlineData("http://[::1]:8080/")]
    [InlineData("http://[::]/")]
    [InlineData("http://[fd12:3456::1]/")]
    [InlineData("http://[fe80::1%25eth0]/")]
    [InlineData("http://[fec0::1]/")]
    [InlineData("http://[::ffff:127.0.0.1]/")]
    [InlineData("http://[::ffff:a9fe:a9fe]/")]
    [InlineData("http://[::10.0.0.1]/")]
    [InlineData("http://[64:ff9b::a9fe:a9fe]/")]
    [InlineData("http://[2002:c0a8:0101::1]/")]
    [InlineData("http://[::1/")]
    // Userinfo tricks: the host is after the last '@', whatever the userinfo
    // holds - URL parsers read up to the path, not up to a comma or quote.
    [InlineData("http://example.com@127.0.0.1/")]
    [InlineData("http://user:pass@10.0.0.1/")]
    [InlineData("http://a,@169.254.169.254/latest/meta-data/")]
    [InlineData("http://x'@127.0.0.1:6379/")]
    [InlineData("http://x)@10.0.0.5/")]
    [InlineData("http://a b@127.0.0.1/")]
    [InlineData("http://a\"<>`@169.254.169.254")]
    // Tabs and newlines, which URL parsers delete before parsing.
    [InlineData("ht\ttp://169.254.169.254/")]
    [InlineData("ht\ntp://169.254.169.254/")]
    [InlineData("http://\t127.0.0.1/")]
    [InlineData("http:/\t/127.0.0.1/")]
    [InlineData("http://127.0.\r\n0.1/")]
    // Full-width, enclosed and percent-encoded UTF-8 forms that IDNA folds.
    [InlineData("http://１２７.０.０.１/")]
    [InlineData("http://①②⑦.⓪.⓪.①/")]
    [InlineData("http://ｌｏｃａｌｈｏｓｔ/")]
    [InlineData("http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ:8080/")]
    [InlineData("http://%EF%BC%91%EF%BC%92%EF%BC%97.0.0.1/")]
    [InlineData("http://127%252e0%252e0%252e1/")]
    // Leading zeros, which inet_aton accepts in any number.
    [InlineData("http://0x00000000007f000001/")]
    [InlineData("http://000000000000177.0.0.1/")]
    [InlineData("http://0000000000000177.0.0.1/")]
    [InlineData("http://00/")]
    // Lenient slashes, other schemes, URLs inside larger strings.
    [InlineData("http:\\\\127.0.0.1\\")]
    [InlineData("http:/127.0.0.1/")]
    [InlineData("http:／／127.0.0.1/")]
    [InlineData("ws://localhost:9229/")]
    [InlineData("wss://10.0.0.1/socket")]
    [InlineData("ftp://192.168.0.10/pub")]
    [InlineData("fetch this: http://169.254.169.254/ then summarise it")]
    [InlineData("url=http://localhost")]
    [InlineData("(http://127.0.0.1)")]
    [InlineData("first http://10.0.0.1, then more")]
    [InlineData("see https://example.com and also http://10.0.0.1")]
    [InlineData("http://localhost?x=1")]
    [InlineData("http://localhost#frag")]
    [InlineData("'http://localhost'")]
    // Dangerous whatever the host.
    [InlineData("file:///etc/passwd")]
    [InlineData("FILE:/c:/windows/win.ini")]
    [InlineData("gopher://example.com:70/_SET%20key")]
    [InlineData("dict://example.com:11211/stats")]
    public void Fires_OnInternalAddresses(string value) => Assert.True(SsrfDetector.IsMatch(value));

    [Theory]
    [InlineData("https://example.com/")]
    [InlineData("https://api.github.com/repos/o/r")]
    [InlineData("http://8.8.8.8/")]
    [InlineData("http://172.32.0.1/")]
    [InlineData("http://172.15.255.255/")]
    [InlineData("http://192.169.0.1/")]
    [InlineData("http://100.128.0.1/")]
    [InlineData("http://169.255.0.1/")]
    [InlineData("http://[2001:db8::1]/")]
    [InlineData("http://[2002:0808:0808::1]/")]
    [InlineData("http://[64:ff9b::808:808]/")]
    [InlineData("http://localhost.example.com/")]
    [InlineData("http://internal.example.com/")]
    [InlineData("http://mylocalhost/")]
    // Not URLs at all.
    [InlineData("")]
    [InlineData("no colon here")]
    [InlineData("time: 10:30")]
    [InlineData("C:\\Users\\me\\file.txt")]
    [InlineData("http: the protocol")]
    [InlineData("profile:/x")]
    [InlineData("myhttp://localhost")]
    [InlineData("x-file:///etc/passwd")]
    [InlineData("1http://localhost")]
    [InlineData("a+http://localhost")]
    [InlineData("a.http://localhost")]
    [InlineData("mailto:root@localhost")]
    [InlineData("file: notes.txt")]
    [InlineData("trailing colon:")]
    [InlineData(":")]
    [InlineData("http://")]
    // Hosts that are numeric-looking but not valid inet_aton forms.
    [InlineData("http://1.2.3.4.5/")]
    [InlineData("http://08.0.0.1/")]
    [InlineData("http://0x/")]
    [InlineData("http://0xg/")]
    [InlineData("http://256.0.0.1/")]
    [InlineData("http://1.2.3.256/")]
    [InlineData("http://1.2.65536/")]
    [InlineData("http://4294967296/")]
    [InlineData("http://123456789012/")]
    [InlineData("http://1..2/")]
    [InlineData("http://[not-an-address]/")]
    [InlineData("http://[::zz]/")]
    [InlineData("http://%ff%fe/")]
    [InlineData("http://%zz/")]
    [InlineData("http://example.com%/")]
    [InlineData("http://0x1000000000000/")]
    // A '@' after the URL that leads to a public host changes nothing.
    [InlineData("see https://example.com and email bob@corp.example.com today")]
    [InlineData("http://a,@example.com/")]
    [InlineData("http://１.２.３.４/")]
    [InlineData("first line\thttps://example.com/")]
    public void StaysQuiet_OnOrdinaryValues(string value) => Assert.False(SsrfDetector.IsMatch(value));

    [Fact]
    public void AColonInsideAnAuthority_IsNotReadAsAnotherScheme()
    {
        // The port's colon is skipped with the authority, and the URL after the
        // path is still found.
        Assert.True(SsrfDetector.IsMatch("http://example.com:443/redirect?to=x http://localhost"));
        Assert.False(SsrfDetector.IsMatch("http://example.com:443/a:b"));
    }

    [Theory]
    [InlineData("127.0.0.1", 0x7F000001u)]
    [InlineData("2130706433", 0x7F000001u)]
    [InlineData("0x7f.1", 0x7F000001u)]
    [InlineData("0177.0.0.1", 0x7F000001u)]
    [InlineData("10.1.257", 0x0A010101u)]
    [InlineData("0", 0u)]
    [InlineData("037777777777", 0xFFFFFFFFu)]
    [InlineData("0x00000000007f000001", 0x7F000001u)]
    [InlineData("000000000000177.0.0.1", 0x7F000001u)]
    [InlineData("00", 0u)]
    public void ParsesIPv4_LikeInetAton(string host, uint expected)
    {
        Assert.True(SsrfDetector.TryParseIPv4(host, out var address));
        Assert.Equal(expected, address);
    }

    [Theory]
    [InlineData("")]
    [InlineData("1.2.3.4.5")]
    [InlineData("1.2.3.")]
    [InlineData("999999999999")]
    [InlineData("example")]
    public void RejectsHosts_ThatAreNotIPv4(string host) => Assert.False(SsrfDetector.TryParseIPv4(host, out _));

    [Fact]
    public void ALongValue_IsScannedInLinearTime()
    {
        // Every colon is a candidate scheme end; none is, and none may cause
        // a rescan of what came before it.
        // A quadratic scan of this would take minutes; see PathDetectorsTests
        // for why the input is sized as it is.
        var adversarial = string.Concat(Enumerable.Repeat("http:x", 100_000)) +
                          string.Concat(Enumerable.Repeat("a:", 100_000)) +
                          string.Concat(Enumerable.Repeat("http://a,b c@d ", 50_000)) +
                          "http://" + new string(',', 200_000) + "@x" +
                          "\t" + string.Concat(Enumerable.Repeat("%2", 100_000)) +
                          "http://" + new string('a', 200_000) + ":" + new string('1', 200_000);

        var started = System.Diagnostics.Stopwatch.StartNew();
        Assert.False(SsrfDetector.IsMatch(adversarial));
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(5), $"took {started.Elapsed}");
    }
}
