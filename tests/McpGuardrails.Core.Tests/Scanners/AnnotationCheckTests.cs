using System.Text.Json;
using McpGuardrails.Core.Scanners;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Tests.Scanners;

/// <summary>
/// Tests for the read-only sanity check: a tool that declares
/// <c>readOnlyHint: true</c> while its name or description says it writes.
/// </summary>
public sealed class AnnotationCheckTests
{
    private static Tool Tool(string name, string? description = null, bool? readOnly = true) => new()
    {
        Name = name,
        Description = description,
        InputSchema = JsonDocument.Parse("""{"type":"object"}""").RootElement.Clone(),
        Annotations = readOnly is null ? null : new ToolAnnotations { ReadOnlyHint = readOnly },
    };

    [Fact]
    public void Null_IsRejected() =>
        Assert.Throws<ArgumentNullException>(() => AnnotationCheck.Check(null!));

    [Theory]
    [InlineData(false)]
    [InlineData(null)]
    public void ToolsNotClaimingReadOnly_AreNeverReported(bool? readOnly) =>
        Assert.Empty(AnnotationCheck.Check(Tool("delete_file", "Deletes a file.", readOnly)));

    [Fact]
    public void AnnotationsWithoutReadOnlyHint_AreNotReported()
    {
        var tool = Tool("delete_file", "Deletes a file.", readOnly: null);
        tool.Annotations = new ToolAnnotations { DestructiveHint = true };

        Assert.Empty(AnnotationCheck.Check(tool));
    }

    [Fact]
    public void AReadOnlyDeleteTool_IsReportedForItsNameAndDescription()
    {
        var mismatches = AnnotationCheck.Check(Tool("delete_file", "Removes the file at the given path."));

        Assert.Equal(
            [new AnnotationMismatch("name", "delete"), new AnnotationMismatch("description", "remove")],
            mismatches);
    }

    [Fact]
    public void AnHonestReadOnlyTool_IsClean() =>
        Assert.Empty(AnnotationCheck.Check(Tool("read_file", "Reads the complete contents of a file.")));

    [Fact]
    public void NoDescription_OnlyTheNameIsChecked()
    {
        Assert.Equal([new AnnotationMismatch("name", "send")], AnnotationCheck.Check(Tool("send_email", null)));
        Assert.Empty(AnnotationCheck.Check(Tool("get_mail", string.Empty)));
    }

    [Theory]
    [InlineData("deleteFile", "delete")]
    [InlineData("fileDelete", "delete")]
    [InlineData("DROP_TABLE", "drop")]
    [InlineData("execute-sql", "execute")]
    [InlineData("update2", "update")]
    [InlineData("writeFile", "write")]
    public void Names_AreSplitOnSeparatorsDigitsAndCamelCase(string name, string verb) =>
        Assert.Equal(verb, AnnotationCheck.FirstVerb(name, splitCamelCase: true));

    [Theory]
    [InlineData("select_dropdown")]
    [InlineData("sender_name")]
    [InlineData("updater")]
    [InlineData("overwriting")]
    [InlineData("list")]
    public void OnlyWholeWordsFromTheVocabularyMatch(string name) =>
        Assert.Null(AnnotationCheck.FirstVerb(name, splitCamelCase: true));

    [Theory]
    [InlineData("It wrote the report.", "write")]
    [InlineData("The message was sent", "send")]
    [InlineData("Executing queries, safely.", "execute")]
    [InlineData("Dropped rows are gone", "drop")]
    [InlineData("Lists rows; nothing is UPDATED.", "update")]
    public void Descriptions_MatchInflectionsInAnyCase(string description, string verb) =>
        Assert.Equal(verb, AnnotationCheck.FirstVerb(description, splitCamelCase: false));

    [Fact]
    public void Descriptions_AreNotSplitOnCamelCase()
    {
        // In prose a capital inside a word is a brand name, not two words.
        Assert.Null(AnnotationCheck.FirstVerb("Works with reDeleted items", splitCamelCase: false));
        Assert.Equal("delete", AnnotationCheck.FirstVerb("reDeleted", splitCamelCase: true));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("--- 123 ---")]
    public void TextWithoutWords_HasNoVerb(string? text) =>
        Assert.Null(AnnotationCheck.FirstVerb(text, splitCamelCase: true));

    [Fact]
    public void TheVocabulary_MapsEveryFormToItsVerb()
    {
        Assert.Equal("write", AnnotationCheck.Verbs["written"]);
        Assert.Equal(7, AnnotationCheck.Verbs.Values.Distinct().Count());
    }
}
