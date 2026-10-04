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
            [new AnnotationMismatch("name", "delete"), new AnnotationMismatch("description", "remove", Advisory: true)],
            mismatches);
    }

    [Fact]
    public void ADescriptionMatch_IsAdvisory_SoDenialsDoNotFailAScan()
    {
        // "never deletes anything" is honest, and matches as readily as a lie.
        var mismatch = Assert.Single(AnnotationCheck.Check(Tool("read_file", "Reads a file; never deletes anything.")));

        Assert.Equal(new AnnotationMismatch("description", "delete", Advisory: true), mismatch);
    }

    [Theory]
    [InlineData("get_updates")] // Telegram's read-only getUpdates
    [InlineData("getUpdates")]
    [InlineData("list_sent_messages")]
    [InlineData("search_deleted_items")]
    [InlineData("get_settings")]
    [InlineData("reset_view")]
    [InlineData("run_query")]
    [InlineData("get_post")]
    [InlineData("list_edits")]
    public void ReadToolNames_ThatOnlyContainANounOrParticiple_AreNotReported(string name) =>
        Assert.Empty(AnnotationCheck.Check(Tool(name)));

    [Theory]
    [InlineData("create_directory", "create")]
    [InlineData("move_file", "move")]
    [InlineData("edit_file", "edit")]
    [InlineData("rename_file", "rename")]
    [InlineData("kill_process", "kill")]
    [InlineData("exec", "execute")]
    [InlineData("insert_row", "insert")]
    [InlineData("set_config", "set")]
    [InlineData("truncate_table", "truncate")]
    [InlineData("purge_cache", "purge")]
    [InlineData("overwrite_file", "overwrite")]
    [InlineData("modifyRecord", "modify")]
    public void ReadOnlyToolsNamedLikeAWrite_AreReported(string name, string verb) =>
        Assert.Equal([new AnnotationMismatch("name", verb)], AnnotationCheck.Check(Tool(name)));

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
        Assert.Equal(verb, AnnotationCheck.FirstVerb(name, inName: true));

    [Theory]
    [InlineData("select_dropdown")]
    [InlineData("sender_name")]
    [InlineData("updater")]
    [InlineData("overwriting")]
    [InlineData("deleted")]
    [InlineData("list")]
    [InlineData("averyveryverylongwordindeed")]
    public void OnlyWholeWordsFromTheVocabularyMatch(string name) =>
        Assert.Null(AnnotationCheck.FirstVerb(name, inName: true));

    [Theory]
    [InlineData("It wrote the report.", "write")]
    [InlineData("The message was sent", "send")]
    [InlineData("Executing queries, safely.", "execute")]
    [InlineData("Dropped rows are gone", "drop")]
    [InlineData("Lists rows; nothing is UPDATED.", "update")]
    public void Descriptions_MatchInflectionsInAnyCase(string description, string verb) =>
        Assert.Equal(verb, AnnotationCheck.FirstVerb(description, inName: false));

    [Fact]
    public void Descriptions_AreNotSplitOnCamelCase()
    {
        // In prose a capital inside a word is a brand name, not two words.
        Assert.Null(AnnotationCheck.FirstVerb("Works with reDeleted items", inName: false));
        Assert.Equal("delete", AnnotationCheck.FirstVerb("reDelete", inName: true));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("--- 123 ---")]
    public void TextWithoutWords_HasNoVerb(string? text) =>
        Assert.Null(AnnotationCheck.FirstVerb(text, inName: true));

    [Fact]
    public void TheVocabulary_MapsEveryFormToItsVerb()
    {
        Assert.Equal("write", AnnotationCheck.Verbs["written"]);
        Assert.Equal("execute", AnnotationCheck.NameVerbs["exec"]);

        // Every name verb is also a description verb, except "set": in prose it
        // is mostly a noun.
        Assert.Equal(
            ["set"],
            AnnotationCheck.NameVerbs.Values.Except(AnnotationCheck.Verbs.Values).ToArray());
        Assert.False(AnnotationCheck.NameVerbs.ContainsKey("deleted"));
    }
}
