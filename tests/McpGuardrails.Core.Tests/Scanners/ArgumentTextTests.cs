using McpGuardrails.Core.Scanners;

namespace McpGuardrails.Core.Tests.Scanners;

/// <summary>
/// The text rules the argument detectors share: decoding escapes the way
/// lenient servers do, and folding the look-alike characters IDNA maps to ASCII.
/// </summary>
public sealed class ArgumentTextTests
{
    [Theory]
    [InlineData("%2e%2E", "..")]
    [InlineData("%252e", ".")]
    [InlineData("%25252e", ".")]
    // Three passes and no more, so decoding stays linear.
    [InlineData("%2525252e", "%2e")]
    [InlineData("%u002e%U002F", "./")]
    [InlineData("%u00zz", "%u00zz")]
    [InlineData("%u12", "%u12")]
    [InlineData("%c0%ae%c0%af%c1%9c", "./\\")]
    [InlineData("%e0%80%ae%e0%80%af", "./")]
    [InlineData("%c0%41", "%c0A")]
    [InlineData("%e0%80%41", "%e0%80A")]
    [InlineData("%e0%a4%85", "अ")]
    [InlineData("%EF%BC%91", "１")]
    [InlineData("%F0%9F%98%80", "😀")]
    [InlineData("%c3", "%c3")]
    [InlineData("%c0", "%c0")]
    [InlineData("%e0%80", "%e0%80")]
    [InlineData("%zz", "%zz")]
    [InlineData("100%", "100%")]
    [InlineData("%2", "%2")]
    [InlineData("%41%", "A%")]
    public void Decode_UndoesTheEncodingsServersAccept(string value, string expected) =>
        Assert.Equal(expected, ArgumentText.Decode(value));

    [Fact]
    public void Decode_ReturnsTheValueItself_WhenThereIsNothingToDecode()
    {
        const string plain = "plain/path";

        Assert.Same(plain, ArgumentText.Decode(plain));
    }

    [Theory]
    [InlineData("ｌｏｃａｌｈｏｓｔ", "localhost")]
    [InlineData("127。0｡0․1﹒", "127.0.0.1.")]
    [InlineData("①⑳", "120")]
    [InlineData("⒈⒛", "1.20.")]
    [InlineData("⓪⓿", "00")]
    [InlineData("⓫⓴", "1120")]
    [InlineData("⓵⓾", "110")]
    [InlineData("❶❿", "110")]
    [InlineData("➀➉", "110")]
    [InlineData("➊➓", "110")]
    [InlineData("ⒶⓏ", "az")]
    [InlineData("ⓐⓩ", "az")]
    [InlineData("¹²³⁰⁴⁹₀₉", "12304909")]
    [InlineData("𝟎𝟗𝟘𝟡𝟿", "09099")]
    [InlineData("é", "é")]
    [InlineData("😀", "😀")]
    [InlineData("\U00010000", "\U00010000")]
    [InlineData("\ud800x", "\ud800x")]
    public void FoldHost_MapsCompatibilityFormsToAscii(string host, string expected) =>
        Assert.Equal(expected, ArgumentText.FoldHost(host));

    [Fact]
    public void FoldHost_ReturnsAnAsciiHostItself()
    {
        const string host = "example.com";

        Assert.Same(host, ArgumentText.FoldHost(host));
    }

    [Theory]
    [InlineData("a b", true)]
    [InlineData("a\u2003b", true)]
    [InlineData("a\u1680b", true)]
    [InlineData("a\u0085b", true)]
    [InlineData("a\u3000b", true)]
    [InlineData("a\u200bb", false)]
    [InlineData("ab", false)]
    public void HasWhitespace_AgreesWithCharIsWhiteSpace(string value, bool expected) =>
        Assert.Equal(expected, ArgumentText.HasWhitespace(value));

    [Fact]
    public void CharacterClasses()
    {
        Assert.True(ArgumentText.IsSeparator('／'));
        Assert.False(ArgumentText.IsSeparator('.'));
        Assert.True(ArgumentText.IsWordBreak('`'));
        Assert.True(ArgumentText.IsWordBreak(' '));
        Assert.False(ArgumentText.IsWordBreak('/'));
        Assert.True(ArgumentText.IsStrippedFromUrls('\r'));
        Assert.False(ArgumentText.IsStrippedFromUrls(' '));
    }
}
