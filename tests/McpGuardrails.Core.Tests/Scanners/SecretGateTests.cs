using System.Text.Json;
using System.Text.Json.Nodes;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Scanners;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Tests.Scanners;

/// <summary>
/// Tests for what the proxy does with a secret once one is found: what the
/// server receives, what the model sees, and what the audit log is told.
/// </summary>
public sealed class SecretGateTests
{
    private const string _clean = "Successfully wrote 42 bytes.";

    private static SecretGate Gate(
        SecretArgumentAction arguments = SecretArgumentAction.RedactAudit,
        SecretResultAction results = SecretResultAction.Redact,
        bool pii = false) =>
        new(new SecretScannerSettings { Arguments = arguments, Results = results, Pii = pii });

    private static CallToolResult Result(params string[] texts)
    {
        var result = new CallToolResult();

        foreach (var text in texts)
        {
            result.Content.Add(new TextContentBlock { Text = text });
        }

        return result;
    }

    private static string AllText(CallToolResult result) =>
        string.Join("\n", result.Content.OfType<TextContentBlock>().Select(block => block.Text));

    private static JsonElement Json(string json)
    {
        using var document = JsonDocument.Parse(json);

        return document.RootElement.Clone();
    }

    private static Dictionary<string, JsonElement> Arguments(string content) => new()
    {
        ["path"] = Json("\"/tmp/notes.txt\""),
        ["content"] = Json($"\"{JsonEncodedText.Encode(content)}\""),
    };

    private static Dictionary<string, JsonElement> Dirty() =>
        Arguments($"aws_access_key_id = {SecretSamples.AwsAccessKey}");

    private static readonly Decision _allow = new(Verdict.Allow, "allowed", "allow-writes") { Cost = 3 };

    // ---------------------------------------------------------- guard rails

    [Fact]
    public void NullSettings_AreARejectedArgument()
    {
        Assert.Throws<ArgumentNullException>(() => new SecretGate(null!));
    }

    [Fact]
    public void ANullResult_IsARejectedArgument()
    {
        Assert.Throws<ArgumentNullException>(() => Gate().Inspect(null!, "fs__read"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void ANamelessTool_IsARejectedArgument(string? toolName)
    {
        Assert.ThrowsAny<ArgumentException>(() => Gate().Inspect(Result(_clean), toolName!));
    }

    [Fact]
    public void ANullDecisionOrScan_IsARejectedArgument()
    {
        Assert.Throws<ArgumentNullException>(() => Gate().Apply(null!, null));
        Assert.Throws<ArgumentNullException>(() => Gate().DescribeArguments(null!, null));
    }

    // --------------------------------------------------- arguments: audit log

    [Fact]
    public void ScanArguments_RedactsTheCopyForTheLogAndKeepsTheOriginal()
    {
        var arguments = Dirty();

        var scan = Gate().ScanArguments(arguments);

        Assert.Equal([SecretScanner.AwsAccessKey], scan.Report.Detectors);
        Assert.Equal("aws_access_key_id = [REDACTED:aws-access-key]", scan.Redacted!["content"].GetString());
        Assert.Equal("/tmp/notes.txt", scan.Redacted["path"].GetString());
        Assert.Contains(SecretSamples.AwsAccessKey, scan.Arguments!["content"].GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public void ScanArguments_CleanArgumentsAreLoggedAsSent()
    {
        var scan = Gate().ScanArguments(Arguments(_clean));

        Assert.True(scan.Report.IsClean);
        Assert.Same(scan.Arguments, scan.Redacted);
    }

    [Fact]
    public void ScanArguments_NoArgumentsIsClean()
    {
        var scan = Gate().ScanArguments(null);

        Assert.Null(scan.Redacted);
        Assert.True(scan.Report.IsClean);
    }

    [Fact]
    public void ScanArguments_OffLogsTheSecretVerbatim()
    {
        // The documented opt-out, for a log that is itself a secret store.
        var scan = Gate(arguments: SecretArgumentAction.Off).ScanArguments(Dirty());

        Assert.True(scan.Report.IsClean);
        Assert.Contains(SecretSamples.AwsAccessKey, scan.Redacted!["content"].GetString(), StringComparison.Ordinal);
    }

    // ---------------------------------------------------- arguments: block

    [Fact]
    public void Apply_UnderBlock_RefusesAndNamesTheDetectorNotTheValue()
    {
        var decision = Gate(arguments: SecretArgumentAction.Block).Apply(_allow, Dirty());

        Assert.Equal(Verdict.Deny, decision.Verdict);
        Assert.Equal(SecretGate.ArgumentRule, decision.RuleName);
        Assert.Equal(DecisionSource.Scanner, decision.Source);
        Assert.Equal(3, decision.Cost);
        Assert.Null(decision.Trail);
        Assert.Contains("1 sensitive value (aws-access-key)", decision.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain(SecretSamples.AwsAccessKey, decision.Reason, StringComparison.Ordinal);
        Assert.StartsWith(
            "Blocked by guardrails scanner 'secrets.arguments':",
            decision.ToModelMessage(),
            StringComparison.Ordinal);
    }

    [Fact]
    public void Apply_UnderBlock_ExtendsAnExplainTrail()
    {
        var traced = _allow with { Trail = ["rule 'allow-writes' matched -> allow"] };

        var decision = Gate(arguments: SecretArgumentAction.Block).Apply(traced, Dirty());

        Assert.Equal(
            ["rule 'allow-writes' matched -> allow", "scanner 'secrets': arguments contain aws-access-key -> deny"],
            decision.Trail);
    }

    [Fact]
    public void Apply_UnderBlock_OverridesRequireApproval()
    {
        // A human approving the call would not see the key buried in it.
        var pending = new Decision(Verdict.RequireApproval, "needs a human", "ask");

        var decision = Gate(arguments: SecretArgumentAction.Block).Apply(pending, Dirty());

        Assert.Equal(Verdict.Deny, decision.Verdict);
    }

    [Fact]
    public void Apply_CountsEverySecretInTheReason()
    {
        var arguments = Arguments($"{SecretSamples.AwsAccessKey} {SecretSamples.StripeKey}");

        var decision = Gate(arguments: SecretArgumentAction.Block).Apply(_allow, arguments);

        Assert.Contains("2 sensitive values (aws-access-key, stripe-key)", decision.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Apply_LeavesAPolicyDenialAlone()
    {
        // The first refusal is the one the model hears about.
        var denied = new Decision(Verdict.Deny, "no", "deny-all");

        Assert.Same(denied, Gate(arguments: SecretArgumentAction.Block).Apply(denied, Dirty()));
    }

    [Theory]
    [InlineData(SecretArgumentAction.RedactAudit)]
    [InlineData(SecretArgumentAction.Redact)]
    [InlineData(SecretArgumentAction.Off)]
    public void Apply_OnlyRefusesUnderBlock(SecretArgumentAction action)
    {
        Assert.Same(_allow, Gate(arguments: action).Apply(_allow, Dirty()));
    }

    [Fact]
    public void Apply_PassesCleanOrMissingArguments()
    {
        var gate = Gate(arguments: SecretArgumentAction.Block);

        Assert.Same(_allow, gate.Apply(_allow, Arguments(_clean)));
        Assert.Same(_allow, gate.Apply(_allow, null));
    }

    // --------------------------------------------------- arguments: redact

    [Fact]
    public void RedactForwarded_UnderRedact_ReplacesTheSecretForTheServer()
    {
        var forwarded = Gate(arguments: SecretArgumentAction.Redact).RedactForwarded(Dirty());

        Assert.Equal("aws_access_key_id = [REDACTED:aws-access-key]", forwarded!["content"].GetString());
    }

    [Fact]
    public void RedactForwarded_ForwardsAsSentOtherwise()
    {
        Assert.Null(Gate(arguments: SecretArgumentAction.Redact).RedactForwarded(Arguments(_clean)));
        Assert.Null(Gate(arguments: SecretArgumentAction.Redact).RedactForwarded(null));
        Assert.Null(Gate(arguments: SecretArgumentAction.RedactAudit).RedactForwarded(Dirty()));
    }

    // ------------------------------------------------- arguments: audit fate

    [Fact]
    public void DescribeArguments_NamesWhatBecameOfTheSecret()
    {
        var dirty = Dirty();

        var audit = Gate();
        Assert.Equal("forwarded", audit.DescribeArguments(audit.ScanArguments(dirty), _allow));
        Assert.Equal("forwarded", audit.DescribeArguments(audit.ScanArguments(dirty), null));

        var redact = Gate(arguments: SecretArgumentAction.Redact);
        Assert.Equal("redacted", redact.DescribeArguments(redact.ScanArguments(dirty), _allow));

        var block = Gate(arguments: SecretArgumentAction.Block);
        var refusal = block.Apply(_allow, dirty);
        Assert.Equal("blocked", block.DescribeArguments(block.ScanArguments(dirty), refusal));
    }

    [Fact]
    public void DescribeArguments_IsSilentWhenCleanOrRefusedForAnotherReason()
    {
        var gate = Gate();

        Assert.Null(gate.DescribeArguments(gate.ScanArguments(Arguments(_clean)), _allow));
        Assert.Null(gate.DescribeArguments(
            gate.ScanArguments(Dirty()),
            new Decision(Verdict.Deny, "no", "deny-all")));
    }

    // -------------------------------------------------------------- results

    [Fact]
    public void Inspect_RedactsTheResultAndTellsTheModelWhatTheMarkersAre()
    {
        var outcome = Gate().Inspect(Result($"key: {SecretSamples.AwsAccessKey}"), "fs__read_text_file");

        Assert.Equal(RedactionEffect.Redacted, outcome.Effect);
        Assert.Equal("redacted", outcome.Describe());
        Assert.Equal(2, outcome.Result.Content.Count);
        Assert.Equal("key: [REDACTED:aws-access-key]", ((TextContentBlock)outcome.Result.Content[0]).Text);

        var notice = ((TextContentBlock)outcome.Result.Content[1]).Text;
        Assert.StartsWith("[guardrails] 1 sensitive value was redacted from the output of 'fs__read_text_file'", notice, StringComparison.Ordinal);
        Assert.Contains("do not write them back", notice, StringComparison.Ordinal);
    }

    [Fact]
    public void Inspect_PluralNoticeForSeveralValues()
    {
        var outcome = Gate().Inspect(
            Result(SecretSamples.AwsAccessKey, _clean, SecretSamples.Jwt),
            "fs__read_text_file");

        Assert.Contains("2 sensitive values were redacted", AllText(outcome.Result), StringComparison.Ordinal);
        Assert.Equal([SecretScanner.AwsAccessKey, SecretScanner.Jwt], outcome.Report.Detectors);
    }

    [Fact]
    public void Inspect_KeepsAnnotationsAndTheErrorFlag()
    {
        var annotations = new Annotations { Priority = 0.5f };
        var result = new CallToolResult { IsError = true };
        result.Content.Add(new TextContentBlock { Text = SecretSamples.StripeKey, Annotations = annotations });

        var outcome = Gate().Inspect(result, "shell__run");

        Assert.True(outcome.Result.IsError);
        Assert.Same(annotations, outcome.Result.Content[0].Annotations);
    }

    [Fact]
    public void Inspect_RedactsEmbeddedTextResources()
    {
        var result = new CallToolResult();
        result.Content.Add(new EmbeddedResourceBlock
        {
            Resource = new TextResourceContents
            {
                Uri = "file:///app/.env",
                MimeType = "text/plain",
                Text = $"STRIPE={SecretSamples.StripeKey}",
            },
        });
        result.Content.Add(new EmbeddedResourceBlock
        {
            Resource = new TextResourceContents { Uri = "file:///app/README", Text = _clean },
        });

        var outcome = Gate().Inspect(result, "fs__read_resource");

        var resource = (TextResourceContents)((EmbeddedResourceBlock)outcome.Result.Content[0]).Resource;
        Assert.Equal("STRIPE=[REDACTED:stripe-key]", resource.Text);
        Assert.Equal("file:///app/.env", resource.Uri);
        Assert.Equal("text/plain", resource.MimeType);
        Assert.Same(result.Content[1], outcome.Result.Content[1]);
    }

    [Fact]
    public void Inspect_LeavesBinaryBlocksAlone()
    {
        var image = new ImageContentBlock { Data = new byte[] { 0x89, 0x50 }, MimeType = "image/png" };
        var result = Result(SecretSamples.Jwt);
        result.Content.Add(image);

        var outcome = Gate().Inspect(result, "fs__read_media_file");

        Assert.Same(image, outcome.Result.Content[1]);
    }

    [Fact]
    public void Inspect_RedactsTheStructuredPayload()
    {
        var result = Result(_clean);
        result.StructuredContent = Json("""{"user": "admin", "password": "hunter2"}""");

        var outcome = Gate().Inspect(result, "db__query");

        Assert.Equal(
            "[REDACTED:sensitive-field]",
            outcome.Result.StructuredContent!.Value.GetProperty("password").GetString());
        Assert.Equal("admin", outcome.Result.StructuredContent.Value.GetProperty("user").GetString());
    }

    [Fact]
    public void Inspect_ACleanResultIsTheSameInstance()
    {
        var result = Result(_clean);
        result.StructuredContent = Json("""{"rows": 1}""");

        var outcome = Gate().Inspect(result, "db__query");

        Assert.Same(result, outcome.Result);
        Assert.Equal(RedactionEffect.None, outcome.Effect);
        Assert.Null(outcome.Describe());
    }

    [Fact]
    public void Inspect_ADefaultStructuredPayloadIsNotAskedForItsText()
    {
        var result = Result(_clean);
        result.StructuredContent = default(JsonElement);

        Assert.Equal(RedactionEffect.None, Gate().Inspect(result, "db__query").Effect);
    }

    [Fact]
    public void Inspect_PersonalDataOnlyWhenAskedFor()
    {
        var result = Result("Assigned to jane.doe@example.com");

        Assert.Equal(RedactionEffect.None, Gate().Inspect(result, "jira__get").Effect);
        Assert.Equal(RedactionEffect.Redacted, Gate(pii: true).Inspect(result, "jira__get").Effect);
    }

    [Fact]
    public void Inspect_UnderBlock_WithholdsTheWholeResult()
    {
        var outcome = Gate(results: SecretResultAction.Block).Inspect(
            Result($"key: {SecretSamples.AwsAccessKey}"),
            "fs__read_text_file");

        Assert.Equal(RedactionEffect.Blocked, outcome.Effect);
        Assert.Equal("blocked", outcome.Describe());
        Assert.True(outcome.Result.IsError);

        var text = AllText(outcome.Result);
        Assert.StartsWith("Blocked by guardrails scanner 'secrets': the output of 'fs__read_text_file'", text, StringComparison.Ordinal);
        Assert.DoesNotContain(SecretSamples.AwsAccessKey, text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(SecretResultAction.Redact)]
    [InlineData(SecretResultAction.Block)]
    public void Inspect_AReplacedResult_KeepsTheServersResultMetadata(SecretResultAction action)
    {
        // _meta is protocol bookkeeping for the client, not content, and
        // rebuilding the result is no reason to lose it.
        var result = Result(SecretSamples.AwsAccessKey);
        result.Meta = new JsonObject { ["trace"] = "abc" };

        var outcome = Gate(results: action).Inspect(result, "fs__read_text_file");

        Assert.NotSame(result, outcome.Result);
        Assert.Same(result.Meta, outcome.Result.Meta);
    }

    [Fact]
    public void Inspect_ARedactedBlock_KeepsItsOwnMetadata()
    {
        var meta = new JsonObject { ["source"] = "cache" };
        var result = new CallToolResult();
        result.Content.Add(new TextContentBlock { Text = SecretSamples.StripeKey, Meta = meta });

        var outcome = Gate().Inspect(result, "fs__read_text_file");

        Assert.NotSame(result.Content[0], outcome.Result.Content[0]);
        Assert.Same(meta, outcome.Result.Content[0].Meta);
    }

    [Fact]
    public void Inspect_OffPassesTheResultThrough()
    {
        var result = Result(SecretSamples.AwsAccessKey);

        var outcome = SecretGate.Off.Inspect(result, "fs__read_text_file");

        Assert.Same(result, outcome.Result);
        Assert.Equal(RedactionEffect.None, outcome.Effect);
    }
}
