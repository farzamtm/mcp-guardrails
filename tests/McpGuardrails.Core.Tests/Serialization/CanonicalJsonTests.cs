using System.Text.Json;
using McpGuardrails.Core.Serialization;

namespace McpGuardrails.Core.Tests.Serialization;

/// <summary>
/// Tests for the canonical form pins are hashed over: everything that means the
/// same must hash the same, and everything else must not.
/// </summary>
public sealed class CanonicalJsonTests
{
    private static JsonElement Json(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }

    private static string Canonical(string json) => CanonicalJson.Serialize(Json(json));

    [Fact]
    public void KeyOrder_AndWhitespace_DoNotMatter()
    {
        Assert.Equal(
            Canonical("""{"b":1,"a":{"y":[1,2],"x":"s"}}"""),
            Canonical("""
                {
                  "a": { "x": "s", "y": [ 1, 2 ] },
                  "b": 1
                }
                """));
        Assert.Equal("""{"a":{"x":"s","y":[1,2]},"b":1}""", Canonical("""{"b":1,"a":{"y":[1,2],"x":"s"}}"""));
    }

    [Fact]
    public void Keys_AreSortedByOrdinal_NotByCulture()
    {
        Assert.Equal("""{"B":1,"a":2,"é":3}""", Canonical("""{"é":3,"a":2,"B":1}"""));
    }

    [Fact]
    public void ArrayOrder_Matters()
    {
        Assert.NotEqual(Canonical("[1,2]"), Canonical("[2,1]"));
    }

    [Theory]
    [InlineData("1", "1.0")]
    [InlineData("1", "1e0")]
    [InlineData("1", "10E-1")]
    [InlineData("0.5", "5e-1")]
    [InlineData("0", "-0.0")]
    [InlineData("0", "0.0")]
    [InlineData("100", "1E2")]
    public void Numbers_HaveOneSpelling(string a, string b)
    {
        Assert.Equal(Canonical(a), Canonical(b));
    }

    [Fact]
    public void Numbers_KeepTheirValue()
    {
        Assert.Equal("-42", Canonical("-42"));
        Assert.Equal("0.1", Canonical("0.1"));
        Assert.Equal("1.2345678901234567E+19", Canonical("12345678901234567890"));

        // Beyond a double: no shorter equivalent exists, so the text is kept.
        Assert.Equal("1e400", Canonical("1e400"));
        Assert.NotEqual(Canonical("1"), Canonical("2"));
    }

    [Fact]
    public void Strings_AreComparedByCodePoint()
    {
        // An escape and the character it stands for are the same string.
        Assert.Equal(Canonical("\"\\u00e9\""), Canonical("\"é\""));

        // Precomposed and decomposed forms are not normalized: they are different
        // text to a tokenizer, and the shipped binary cannot normalize anyway.
        Assert.NotEqual(Canonical("\"\\u00e9\""), Canonical("\"e\\u0301\""));
        Assert.Equal("\"<tag> & 'q' \\\"x\\\"\"", Canonical("\"<tag> & 'q' \\\"x\\\"\""));
    }

    [Fact]
    public void Literals_AndAnAbsentValue_AreWritten()
    {
        Assert.Equal("""[true,false,null]""", Canonical("[true, false, null]"));
        Assert.Equal("null", CanonicalJson.Serialize(default));
    }

    [Fact]
    public void DuplicateKeys_HaveOneCanonicalForm()
    {
        Assert.Equal(Canonical("""{"a":2,"a":1}"""), Canonical("""{"a":1,"a":2}"""));
        Assert.Equal("""{"a":1,"a":2}""", Canonical("""{"a":2,"a":1}"""));
    }

    [Fact]
    public void Format_IsIndented_InTheSameOrder()
    {
        var formatted = CanonicalJson.Format(Json("""{"b":1.0,"a":[true]}"""));

        Assert.Contains('\n', formatted);
        Assert.True(formatted.IndexOf("\"a\"", StringComparison.Ordinal) < formatted.IndexOf("\"b\"", StringComparison.Ordinal));
        Assert.Contains("\"b\": 1", formatted);
    }

    [Fact]
    public void Hash_IsTheSha256OfTheCanonicalText()
    {
        var hash = CanonicalJson.Hash(Json("""{ "b": 1, "a": 2 }"""));

        Assert.Equal(CanonicalJson.HashText("""{"a":2,"b":1}"""), hash);
        Assert.Equal(CanonicalJson.Hash(Json("""{"a":2,"b":1.0}""")), hash);
        Assert.NotEqual(CanonicalJson.Hash(Json("""{"a":2,"b":2}""")), hash);

        // echo -n '{}' | shasum -a 256
        Assert.Equal(
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            CanonicalJson.Hash(Json("{}")));
        Assert.True(CanonicalJson.IsHash(hash));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("sha256:abc")]
    [InlineData("md5:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")]
    [InlineData("sha256:44136FA355B3678A1146AD16F7E8649E94FB4FC21FE77E8310C060F61CAAFF8A")]
    [InlineData("sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8z")]
    public void IsHash_RejectsAnythingElse(string? value)
    {
        Assert.False(CanonicalJson.IsHash(value));
    }

    [Fact]
    public void HashText_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => CanonicalJson.HashText(null!));
    }
}
