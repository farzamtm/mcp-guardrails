using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Policy;

public sealed class GlobMatcherTests
{
    [Theory]
    // A pattern with no wildcard is still an exact match, which is what keeps
    // every policy file written before globs existed meaning the same thing.
    [InlineData("fs__write_file", "fs__write_file", true)]
    [InlineData("fs__write_file", "fs__write_file_2", false)]
    [InlineData("fs__write_file", "fs__WRITE_FILE", false)]
    [InlineData("", "", true)]
    [InlineData("", "a", false)]
    public void LiteralPatterns_MatchExactlyAndCaseSensitively(
        string pattern, string value, bool expected) =>
        Assert.Equal(expected, GlobMatcher.IsMatch(pattern, value));

    [Theory]
    [InlineData("*", "anything", true)]
    [InlineData("*", "", true)]
    [InlineData("fs__*", "fs__write_file", true)]
    [InlineData("fs__*", "fs__", true)]
    [InlineData("fs__*", "git__commit", false)]
    // A star crosses the namespace separator, so "*delete*" catches a verb
    // wherever it appears rather than only within one server.
    [InlineData("*delete*", "gh__delete_repo", true)]
    [InlineData("*__delete_*", "gh__delete_repo", true)]
    [InlineData("*__delete_*", "gh__list_repos", false)]
    public void Star_MatchesAnyRunOfCharacters(string pattern, string value, bool expected) =>
        Assert.Equal(expected, GlobMatcher.IsMatch(pattern, value));

    [Theory]
    [InlineData("fs__?", "fs__a", true)]
    [InlineData("fs__?", "fs__ab", false)]
    [InlineData("fs__?", "fs__", false)]
    public void QuestionMark_MatchesExactlyOneCharacter(
        string pattern, string value, bool expected) =>
        Assert.Equal(expected, GlobMatcher.IsMatch(pattern, value));

    [Theory]
    // The backtracking cases: the first '*' must be able to grow when a later
    // literal fails to line up.
    [InlineData("a*bc", "abxbc", true)]
    [InlineData("a*bc", "abxb", false)]
    [InlineData("*.txt", "notes.txt.bak", false)]
    [InlineData("*.txt*", "notes.txt.bak", true)]
    [InlineData("a*b*c", "axxbyyc", true)]
    [InlineData("ab*", "ab", true)]
    [InlineData("ab**", "ab", true)]
    [InlineData("abc", "ab", false)]
    public void Backtracking_HandlesStarsFollowedByLiterals(
        string pattern, string value, bool expected) =>
        Assert.Equal(expected, GlobMatcher.IsMatch(pattern, value));

    [Fact]
    public void PathologicalPattern_StillReturnsPromptly()
    {
        // The reason this is hand-rolled rather than compiled to a regex: a
        // policy file is configuration, and configuration must not be able to
        // hang the proxy. This input is the classic regex-killer.
        var pattern = new string('*', 40) + "b";
        var value = new string('a', 2000);

        Assert.False(GlobMatcher.IsMatch(pattern, value));
    }
}
