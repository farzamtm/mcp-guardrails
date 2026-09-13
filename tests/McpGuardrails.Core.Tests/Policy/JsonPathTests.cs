using System.Text.Json;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Policy;

public sealed class JsonPathTests
{
    private static readonly IReadOnlyDictionary<string, JsonElement> _arguments =
        TestArguments.From("""
            {
              "limit": 500,
              "path": "/etc/passwd",
              "options": { "recursive": true, "depth": 2 },
              "files": ["a.txt", "b.txt"],
              "content-type": "text/plain",
              "matrix": [[1, 2], [3, 4]]
            }
            """);

    private static string? Resolve(string path) =>
        JsonPath.TryResolve(_arguments, path, out var value) ? value.ToString() : null;

    // ------------------------------------------------------------ what resolves

    [Theory]
    [InlineData("$.limit", "500")]
    [InlineData("limit", "500")]
    [InlineData("$.path", "/etc/passwd")]
    [InlineData("$.options.recursive", "True")]
    [InlineData("$.options.depth", "2")]
    [InlineData("$.files[0]", "a.txt")]
    [InlineData("$.files[1]", "b.txt")]
    [InlineData("$.matrix[1][0]", "3")]
    [InlineData("$['content-type']", "text/plain")]
    [InlineData("$[\"limit\"]", "500")]
    public void TryResolve_WalksTheSupportedSyntax(string path, string expected) =>
        Assert.Equal(expected, Resolve(path));

    // -------------------------------------------------------- what does not

    [Theory]
    // Absent is not an error and not a match; see the note on ArgumentPredicate.
    [InlineData("$.missing")]
    [InlineData("$.options.missing")]
    [InlineData("$.files[9]")]
    // A scalar has no members, and an object has no index.
    [InlineData("$.limit.nested")]
    [InlineData("$.options[0]")]
    // "$" alone names the whole argument object, which no operator can use.
    [InlineData("$")]
    [InlineData("")]
    public void TryResolve_ReturnsFalseWhenThePathLeadsNowhere(string path) =>
        Assert.Null(Resolve(path));

    [Fact]
    public void TryResolve_ReturnsFalseWhenThereAreNoArguments() =>
        Assert.False(JsonPath.TryResolve(null, "$.limit", out _));

    [Theory]
    // Malformed paths resolve to nothing rather than throwing, because the
    // loader has already rejected them; this is the belt to that braces.
    [InlineData("$..limit")]
    [InlineData("$.")]
    [InlineData("$['limit'")]
    [InlineData("$['limit']x")]
    [InlineData("$['']")]
    [InlineData("$[0]")]
    [InlineData("$[-1]")]
    [InlineData("$.files[x]")]
    public void TryResolve_ReturnsFalseForMalformedPaths(string path) =>
        Assert.Null(Resolve(path));

    // -------------------------------------------------------------- validation

    [Theory]
    [InlineData("$.limit")]
    [InlineData("limit")]
    [InlineData("$.options.depth")]
    [InlineData("$.files[0]")]
    [InlineData("$.matrix[1][0]")]
    [InlineData("$['content-type']")]
    [InlineData("$[\"content-type\"]")]
    public void IsWellFormed_AcceptsTheSupportedSubset(string path) =>
        Assert.True(JsonPath.IsWellFormed(path));

    [Theory]
    // Unsupported JSONPath is rejected at load rather than silently never
    // matching: a rule that quietly does nothing is worse than one that fails.
    [InlineData("$..limit")]
    [InlineData("$.*")]
    [InlineData("$.items[*]")]
    [InlineData("$.items[1:2]")]
    [InlineData("$.")]
    [InlineData("$")]
    [InlineData("")]
    [InlineData("$['limit'")]
    [InlineData("$['']")]
    [InlineData("$['a']b")]
    // Indexing the argument object itself: arguments are always named.
    [InlineData("$[0]")]
    public void IsWellFormed_RejectsEverythingElse(string path) =>
        Assert.False(JsonPath.IsWellFormed(path));

    [Fact]
    public void IsWellFormed_AcceptsAWildcardAsAPlainPropertyName()
    {
        // "$.*" is rejected above as a glob, but a quoted "*" is a legitimate
        // property name and must still resolve.
        Assert.True(JsonPath.IsWellFormed("$['*']"));

        var arguments = TestArguments.From("""{ "*": "star" }""");

        Assert.True(JsonPath.TryResolve(arguments, "$['*']", out var value));
        Assert.Equal("star", value.GetString());
    }
}
