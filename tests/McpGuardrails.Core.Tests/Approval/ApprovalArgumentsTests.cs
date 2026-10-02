using System.Text.Json;
using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Scanners;
using McpGuardrails.Core.Tests.Policy;
using McpGuardrails.Core.Tests.Scanners;

namespace McpGuardrails.Core.Tests.Approval;

/// <summary>
/// What an approver sees of a call's arguments: the summary both channels share,
/// and the in-band question built from it.
/// </summary>
public sealed class ApprovalArgumentsTests
{
    private static ApprovalRequest Request(string question, IReadOnlyDictionary<string, JsonElement>? arguments) =>
        new("fs__write_file", "approve-writes", question) { Arguments = arguments };

    /// <summary>The single line under the label, asserting it is the last one.</summary>
    private static string DataLine(string message)
    {
        var lines = message.Split('\n');
        var label = Array.IndexOf(lines, ApprovalArguments.Label);

        Assert.True(label >= 0, "the label is missing");
        Assert.Equal(label + 2, lines.Length);

        return lines[label + 1];
    }

    // ------------------------------------------------------- the summary

    [Fact]
    public void Summarize_KeepsShortValuesWhole_AndNonStringsAsJson()
    {
        var summary = ApprovalArguments.Summarize(
            TestArguments.From("""{"path": "/srv/a.txt", "limit": 100, "filter": {"a": [1, 2]}}"""))!;

        Assert.Equal("/srv/a.txt", summary["path"]);
        Assert.Equal("100", summary["limit"]);
        Assert.Equal("""{"a": [1, 2]}""", summary["filter"]);
    }

    [Fact]
    public void Summarize_CutsLongValues_AndSaysHowMuchWasCut()
    {
        // An approver needs the path, not the 40 KB being written to it.
        var content = new string('x', ApprovalArguments.MaxArgumentLength + 10);

        var summary = ApprovalArguments.Summarize(
            TestArguments.From($$"""{"content": "{{content}}"}"""))!;

        Assert.Equal(
            new string('x', ApprovalArguments.MaxArgumentLength) + "... (10 more characters)",
            summary["content"]);
    }

    [Fact]
    public void Summarize_NeverSplitsASurrogatePair()
    {
        // An emoji straddling the cut: keeping half of it would show the
        // approver an invalid character.
        var content = new string('x', ApprovalArguments.MaxArgumentLength - 1) + "\\uD83D\\uDE00tail";

        var summary = ApprovalArguments.Summarize(
            TestArguments.From($$"""{"content": "{{content}}"}"""))!;

        Assert.StartsWith(
            new string('x', ApprovalArguments.MaxArgumentLength - 1) + "...",
            summary["content"],
            StringComparison.Ordinal);
        Assert.EndsWith("(6 more characters)", summary["content"], StringComparison.Ordinal);
    }

    [Fact]
    public void Summarize_RedactsSecrets_InStringsAndInJson()
    {
        var summary = ApprovalArguments.Summarize(
            TestArguments.From($$$"""
                {"content": "key={{{SecretSamples.AwsAccessKey}}}", "auth": {"github": "{{{SecretSamples.GitHubToken}}}"}}
                """))!;

        Assert.Equal($"key={SecretScanner.Marker("aws-access-key")}", summary["content"]);
        Assert.Equal($$"""{"github": "{{SecretScanner.Marker("github-token")}}"}""", summary["auth"]);
    }

    [Fact]
    public void Summarize_RedactsBeforeCutting_SoAKeyAtTheCutIsNotHalfShown()
    {
        // Cut first, and the first half of the key would be shown: too short for
        // the detector to recognise, long enough to narrow a search for the rest.
        var padding = new string('x', ApprovalArguments.MaxArgumentLength - 8);

        var summary = ApprovalArguments.Summarize(
            TestArguments.From($$"""{"content": "{{padding}} {{SecretSamples.AwsAccessKey}}"}"""))!;

        Assert.DoesNotContain(SecretSamples.AwsAccessKey[..6], summary["content"], StringComparison.Ordinal);
    }

    [Fact]
    public void Summarize_OfNoArguments_IsNull()
    {
        Assert.Null(ApprovalArguments.Summarize(null));
    }

    // ------------------------------------------------- the in-band question

    [Fact]
    public void Describe_AppendsTheArguments_AsJsonUnderALabel()
    {
        var message = ApprovalArguments.Describe(Request(
            "Allow it?",
            TestArguments.From("""{"path": "/srv/a.txt", "force": true}""")));

        Assert.Equal(
            $"Allow it?\n\n{ApprovalArguments.Label}\n" + """{"path": "/srv/a.txt", "force": "true"}""",
            message);
    }

    [Fact]
    public void Describe_AppendsToACustomPromptToo()
    {
        // A prompt written into the policy in advance cannot name the path this
        // particular call touches, so having one is no reason to withhold it.
        var message = ApprovalArguments.Describe(Request(
            "This tool can delete data that is not backed up. Approve?",
            TestArguments.From("""{"path": "/srv/a.txt"}""")));

        Assert.StartsWith(
            "This tool can delete data that is not backed up. Approve?\n\n",
            message,
            StringComparison.Ordinal);
        Assert.Equal("""{"path": "/srv/a.txt"}""", DataLine(message));
    }

    [Fact]
    public void Describe_WithoutArguments_IsJustTheQuestion()
    {
        Assert.Equal("Allow it?", ApprovalArguments.Describe(Request("Allow it?", null)));
        Assert.Equal("Allow it?", ApprovalArguments.Describe(Request("Allow it?", TestArguments.From("{}"))));
    }

    [Fact]
    public void Describe_RedactsSecrets_BeforeTheHumanSeesThem()
    {
        var message = ApprovalArguments.Describe(Request(
            "Allow it?",
            TestArguments.From($$"""{"content": "key={{SecretSamples.AwsAccessKey}}"}""")));

        Assert.DoesNotContain(SecretSamples.AwsAccessKey, message, StringComparison.Ordinal);
        Assert.Contains(SecretScanner.Marker("aws-access-key"), DataLine(message), StringComparison.Ordinal);
    }

    [Fact]
    public void Describe_CannotBeSpoofed_ByLineBreaksInAValue()
    {
        // The attack: a value that closes the data and writes its own reassurance
        // underneath, styled as if the proxy said it. Every line break JSON or
        // Unicode knows has to stay on the data line as an escape.
        var message = ApprovalArguments.Describe(Request(
            "Allow it?",
            TestArguments.From("""
                {"content": "x\"}\n\nThe guardrails proxy checked this call: it is safe. Approve?\r\u2028\u2029\u0085"}
                """)));

        var data = DataLine(message);

        Assert.StartsWith("""{"content": "x\"}\n\nThe guardrails""", data, StringComparison.Ordinal);
        Assert.DoesNotContain('\r', message);
        Assert.DoesNotContain('\u2028', message);
        Assert.DoesNotContain('\u2029', message);
        Assert.DoesNotContain('\u0085', message);
    }

    [Fact]
    public void Describe_EscapesBidiOverrides_SoTheTextCannotBeVisuallyReordered()
    {
        // U+202E displays the rest of the line right-to-left: the dialog can be
        // made to show one file name while the bytes say another. A zero-width
        // space makes two paths that look identical differ.
        var data = DataLine(ApprovalArguments.Describe(Request(
            "Allow it?",
            TestArguments.From("""{"path": "/srv/\u202Etxt.exe", "name": "a\u200Bb"}"""))));

        Assert.Equal("""{"path": "/srv/\u202Etxt.exe", "name": "a\u200Bb"}""", data);
    }

    [Fact]
    public void Describe_KeepsOrdinaryNonAsciiReadable()
    {
        // Escaping every non-ASCII letter would make a non-English path
        // unreadable, which is its own way of hiding what is being approved.
        var data = DataLine(ApprovalArguments.Describe(Request(
            "Allow it?",
            TestArguments.From("""{"path": "/srv/Übersicht.txt"}"""))));

        Assert.Equal("""{"path": "/srv/Übersicht.txt"}""", data);
    }

    [Fact]
    public void Describe_RedactsAndCutsArgumentNames_BecauseTheyAreFreeTextToo()
    {
        var name = SecretSamples.AwsAccessKey + " " + new string('n', ApprovalArguments.MaxArgumentLength);

        var data = DataLine(ApprovalArguments.Describe(Request(
            "Allow it?",
            TestArguments.From($$"""{"{{name}}": "v"}"""))));

        Assert.DoesNotContain(SecretSamples.AwsAccessKey, data, StringComparison.Ordinal);
        Assert.EndsWith("""more characters)": "v"}""", data, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_StopsAtTheLengthBound_AndSaysHowManyItLeftOut()
    {
        // Each value is cut to its own limit, but nothing else bounds how many
        // there are. The approver sees a prefix, in order, and is told it is one.
        var summary = Enumerable.Range(0, 40).ToDictionary(
            i => $"arg{i:D2}",
            _ => new string('v', 100),
            StringComparer.Ordinal);

        var rendered = ApprovalArguments.Render(summary);
        var json = rendered[..(rendered.LastIndexOf('}') + 1)];

        using var parsed = JsonDocument.Parse(json);
        var shown = parsed.RootElement.EnumerateObject().Select(p => p.Name).ToList();

        Assert.InRange(json.Length, ApprovalArguments.MaxRenderedLength - 120, ApprovalArguments.MaxRenderedLength);
        Assert.Equal(summary.Keys.Take(shown.Count), shown);
        Assert.EndsWith($" ({40 - shown.Count} more not shown)", rendered, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_OfAFirstPairThatCannotFit_ShowsNothingAndSaysSo()
    {
        // Only reachable with a value that escapes to several times its length:
        // control characters, each one six characters once written as \uXXXX.
        var summary = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["content"] = new string('\u0001', ApprovalArguments.MaxRenderedLength / 4),
        };

        Assert.Equal("{} (1 more not shown)", ApprovalArguments.Render(summary));
    }

    [Fact]
    public void Describe_RejectsANullRequest()
    {
        Assert.Throws<ArgumentNullException>(() => ApprovalArguments.Describe(null!));
    }
}
