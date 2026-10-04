using McpGuardrails.Core.Text;

namespace McpGuardrails.Core.Tests.Text;

public class TerminalTextTests
{
    [Fact]
    public void OrdinaryText_IsReturnedUnchanged()
    {
        const string Text = "fs__read_file: café ✓";
        Assert.Same(Text, TerminalText.Printable(Text));
        Assert.Same(Text, TerminalText.PrintableLines(Text));
    }

    [Fact]
    public void CharactersJustOutsideEachUnsafeRange_AreKept()
    {
        // Dashes, per-mille, the gaps between the ranges: ordinary punctuation a
        // tool description really uses must survive.
        const string Text = "\u061B\u061D\u200A\u2010\u2027\u202F\u2030\u205F\u2065\u206A\uFEFE\uFF01";
        Assert.Same(Text, TerminalText.Printable(Text));
    }

    [Theory]
    [InlineData("\u001b[2JClean", "?[2JClean")] // ESC: a screen clear
    [InlineData("\u001b]52;c;Y3VybA==\u0007", "?]52;c;Y3VybA==?")] // OSC 52 clipboard write, BEL-terminated
    [InlineData("a\u009bb", "a?b")] // the 8-bit CSI
    [InlineData("a\u007fb", "a?b")] // DEL
    [InlineData("admin\u202Etxt.exe", "admin?txt.exe")] // right-to-left override
    [InlineData("a\u2066b\u2069", "a?b?")] // bidi isolates
    [InlineData("a\u200Bb\u200Dc\uFEFF", "a?b?c?")] // zero-width characters
    [InlineData("a\u2028b\u2029", "a?b?")] // line and paragraph separators
    [InlineData("a\u061Cb\u2060", "a?b?")] // Arabic letter mark, word joiner
    [InlineData("one\ntwo\r\n", "one?two??")] // line breaks too: a name stays one line
    public void Printable_ReplacesEveryCharacterThatCouldControlOrDisguiseOutput(string input, string expected) =>
        Assert.Equal(expected, TerminalText.Printable(input));

    [Fact]
    public void PrintableLines_KeepsLineBreaks_ButNothingElse()
    {
        Assert.Equal("Invalid file:\n  - bad ?[31mred", TerminalText.PrintableLines("Invalid file:\r\n  - bad \u001b[31mred"));
        Assert.Equal("a?b", TerminalText.PrintableLines("a\u0007b"));
    }

    [Fact]
    public void NullIsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => TerminalText.Printable(null!));
        Assert.Throws<ArgumentNullException>(() => TerminalText.PrintableLines(null!));
    }
}
