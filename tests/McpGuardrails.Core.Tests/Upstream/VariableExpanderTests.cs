using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Tests.Upstream;

public sealed class VariableExpanderTests
{
    private static readonly Dictionary<string, string> _environment = new(StringComparer.Ordinal)
    {
        ["TOKEN"] = "t0k3n",
        ["EMPTY"] = "",
        ["UNICODE"] = "größe-🙂",
        ["WITH_COLON"] = "a:b",
    };

    private static string? Lookup(string name) => _environment.GetValueOrDefault(name);

    private static string Expanded(string template)
    {
        var expansion = VariableExpander.Expand(template, Lookup);
        Assert.True(expansion.Succeeded, expansion.Error);
        return expansion.Value!;
    }

    private static string Error(string template)
    {
        var expansion = VariableExpander.Expand(template, Lookup);
        Assert.False(expansion.Succeeded);
        Assert.Null(expansion.Value);
        return expansion.Error!;
    }

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("", "")]
    [InlineData("${TOKEN}", "t0k3n")]
    [InlineData("Bearer ${TOKEN}", "Bearer t0k3n")]
    [InlineData("${TOKEN}${TOKEN}", "t0k3nt0k3n")]
    [InlineData("${env:TOKEN}", "t0k3n")]                     // Cursor / VS Code spelling
    [InlineData("${MISSING:-fallback}", "fallback")]
    [InlineData("${env:MISSING:-fallback}", "fallback")]
    [InlineData("${TOKEN:-fallback}", "t0k3n")]
    [InlineData("${EMPTY:-fallback}", "fallback")]           // empty counts as unset, as in a shell
    [InlineData("${EMPTY}", "")]                              // but set-and-empty is not an error
    [InlineData("${MISSING:-}", "")]
    [InlineData("${MISSING:-http://x:1/y}", "http://x:1/y")] // the default may itself contain ':'
    [InlineData("${WITH_COLON}", "a:b")]
    [InlineData("${UNICODE}/ü", "größe-🙂/ü")]
    [InlineData("$$", "$")]
    [InlineData("$${TOKEN}", "${TOKEN}")]                    // an escaped reference stays literal
    [InlineData("price$5", "price$5")]                        // a lone $ needs no escaping
    [InlineData("end$", "end$")]
    [InlineData("{TOKEN}", "{TOKEN}")]
    public void Expand_ResolvesReferences(string template, string expected) =>
        Assert.Equal(expected, Expanded(template));

    [Fact]
    public void Expand_RefusesAnUnsetVariableWithoutADefault()
    {
        // The deliberate difference from Claude Code, which leaves the literal
        // text in place and launches a server with "${MISSING}" as its token.
        var error = Error("Bearer ${MISSING}");

        Assert.Contains("'${MISSING}'", error, StringComparison.Ordinal);
        Assert.Contains("not set", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Expand_RefusesAnUnterminatedReference() =>
        Assert.Contains("unterminated", Error("x ${TOKEN"), StringComparison.Ordinal);

    [Fact]
    public void Expand_RefusesNestedReferences() =>
        Assert.Contains("nested", Error("${MISSING:-${TOKEN}}"), StringComparison.Ordinal);

    [Fact]
    public void Expand_RefusesVsCodeInputsWithAnExplanation()
    {
        var error = Error("${input:api-token}");

        Assert.Contains("prompted input", error, StringComparison.Ordinal);
        Assert.Contains("environment variable", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("${}")]
    [InlineData("${1ABC}")]
    [InlineData("${A-B}")]
    [InlineData("${env:}")]
    [InlineData("${:-x}")]
    public void Expand_RefusesNamesThatAreNotVariables(string template) =>
        Assert.Contains("not a variable name", Error(template), StringComparison.Ordinal);

    [Fact]
    public void Expand_NeverEchoesAValueInAnError()
    {
        // The second reference fails; the first one's value must not appear.
        var error = Error("${TOKEN} ${MISSING}");

        Assert.DoesNotContain("t0k3n", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Expand_RejectsNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => VariableExpander.Expand(null!, Lookup));
        Assert.Throws<ArgumentNullException>(() => VariableExpander.Expand("x", null!));
    }

    [Theory]
    [InlineData("A", true)]
    [InlineData("_a1", true)]
    [InlineData("", false)]
    [InlineData("9", false)]
    [InlineData("a.b", false)]
    public void IsValidName_FollowsPosix(string name, bool expected) =>
        Assert.Equal(expected, VariableExpander.IsValidName(name));
}
