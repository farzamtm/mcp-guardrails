using System.Diagnostics;
using System.Text.Json;
using McpGuardrails.Core.Scanners;

namespace McpGuardrails.Core.Tests.Scanners;

/// <summary>
/// Tests for the detectors themselves: what they redact, what they leave alone,
/// and that nothing they do can be made slow by the input.
/// </summary>
public sealed class SecretScannerTests
{
    private static SecretRedaction Redact(string text, bool includePii = false) =>
        SecretScanner.Redact(text, includePii);

    private static JsonElement Json(string json)
    {
        using var document = JsonDocument.Parse(json);

        return document.RootElement.Clone();
    }

    public static TheoryData<string, string> Credentials => new()
    {
        { SecretSamples.AwsAccessKey, SecretScanner.AwsAccessKey },
        { SecretSamples.GitHubToken, SecretScanner.GitHubToken },
        { SecretSamples.GitHubFineGrained, SecretScanner.GitHubToken },
        { SecretSamples.SlackToken, SecretScanner.SlackToken },
        { SecretSamples.SlackWebhook, SecretScanner.SlackWebhook },
        { SecretSamples.StripeKey, SecretScanner.StripeKey },
        { SecretSamples.AnthropicKey, SecretScanner.AnthropicKey },
        { SecretSamples.OpenAiKey, SecretScanner.OpenAiKey },
        { SecretSamples.GoogleApiKey, SecretScanner.GoogleApiKey },
        { SecretSamples.Jwt, SecretScanner.Jwt },
        { SecretSamples.PrivateKey, SecretScanner.PrivateKey },
    };

    // ------------------------------------------------------------ credentials

    [Theory]
    [MemberData(nameof(Credentials))]
    public void EachCredentialShape_IsReplacedByAMarkerNamingIt(string secret, string detector)
    {
        var redaction = Redact($"config: {secret} (end)");

        Assert.Equal($"config: [REDACTED:{detector}] (end)", redaction.Text);
        Assert.Equal([detector], redaction.Report.Detectors);
        Assert.Equal(1, redaction.Report.Count);
        Assert.DoesNotContain(secret, redaction.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void CleanText_IsReturnedAsTheSameInstance()
    {
        const string text = "Successfully wrote 42 bytes to notes.txt.";

        var redaction = Redact(text);

        Assert.Same(text, redaction.Text);
        Assert.True(redaction.Report.IsClean);
    }

    [Fact]
    public void EmptyText_IsClean()
    {
        Assert.True(Redact("").Report.IsClean);
    }

    [Fact]
    public void NullText_IsARejectedArgument()
    {
        Assert.Throws<ArgumentNullException>(() => SecretScanner.Redact(null!, includePii: false));
    }

    [Fact]
    public void EveryOccurrence_IsRedactedAndCounted()
    {
        var redaction = Redact($"{SecretSamples.AwsAccessKey} and {SecretSamples.AwsAccessKey}");

        Assert.Equal("[REDACTED:aws-access-key] and [REDACTED:aws-access-key]", redaction.Text);
        Assert.Equal(2, redaction.Report.Count);
        Assert.Single(redaction.Report.Detectors);
    }

    [Fact]
    public void DifferentKinds_AreReportedInTheOrderTheyAppear()
    {
        var redaction = Redact($"{SecretSamples.StripeKey} then {SecretSamples.AwsAccessKey}");

        Assert.Equal([SecretScanner.StripeKey, SecretScanner.AwsAccessKey], redaction.Report.Detectors);
    }

    [Fact]
    public void ATruncatedPrivateKey_IsRedactedToTheEndOfTheText()
    {
        // A paginated read can cut a key in half. Half a key is still a key.
        var text = "key:\n-----BEGIN " + "OPENSSH PRIVATE KEY-----\n" + SecretSamples.PrivateKeyBody;

        Assert.Equal("key:\n[REDACTED:private-key]", Redact(text).Text);
    }

    [Fact]
    public void APrivateKeyWithPemHeaders_IsRedactedWhole()
    {
        // Proc-Type and DEK-Info contain single dashes; a body pattern that
        // stopped at the first dash would leak everything after the headers.
        var text =
            "-----BEGIN " + "RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,AB12\n\n" +
            SecretSamples.PrivateKeyBody + "-----END " + "RSA PRIVATE KEY-----\nafter";

        Assert.Equal("[REDACTED:private-key]\nafter", Redact(text).Text);
    }

    [Fact]
    public void APublicKey_IsLeftAlone()
    {
        var text = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----";

        Assert.True(Redact(text).Report.IsClean);
    }

    [Fact]
    public void AStripePublishableKey_IsLeftAlone()
    {
        Assert.True(Redact("pk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc").Report.IsClean);
    }

    [Fact]
    public void AHyphenatedNameShapedLikeAnOpenAiKey_IsLeftAlone()
    {
        // "sk-" and twenty identifier characters, but no digit: a package name,
        // not a key.
        Assert.True(Redact("pip install sk-learn-contrib-extensions-tools").Report.IsClean);
    }

    [Fact]
    public void AnAnthropicKey_IsNamedAsSuchRatherThanAsOpenAi()
    {
        // Both patterns match; the more specific one is listed first and wins.
        Assert.Equal([SecretScanner.AnthropicKey], Redact(SecretSamples.AnthropicKey).Report.Detectors);
    }

    // ----------------------------------------------------------------- bearer

    [Fact]
    public void ABearerToken_KeepsTheSchemeAndLosesTheToken()
    {
        var redaction = Redact("Authorization: Bearer abcdef0123456789abcdef");

        Assert.Equal("Authorization: Bearer [REDACTED:bearer-token]", redaction.Text);
    }

    [Fact]
    public void TheWordBearerInProse_IsLeftAlone()
    {
        Assert.True(Redact("The bearer responsibilities are listed below.").Report.IsClean);
    }

    [Fact]
    public void ABearerJwt_IsOneRedactionNotTwo()
    {
        // Two detectors over the same span. The overlap merges, and the marker
        // names the more specific of the two.
        var redaction = Redact($"Bearer {SecretSamples.Jwt}");

        Assert.Equal("Bearer [REDACTED:jwt]", redaction.Text);
        Assert.Equal(1, redaction.Report.Count);
    }

    // --------------------------------------------------- credential assignment

    [Theory]
    [InlineData("password=hunter22", "password=[REDACTED:credential-assignment]")]
    [InlineData("DB_PASSWORD: s3cr3t!x", "DB_PASSWORD: [REDACTED:credential-assignment]")]
    [InlineData("api_key = \"abcd\"", "api_key = \"[REDACTED:credential-assignment]\"")]
    [InlineData("secret: 'plainwords'", "secret: '[REDACTED:credential-assignment]'")]
    [InlineData("{\"password\": \"hunter2\"}", "{\"password\": \"[REDACTED:credential-assignment]\"}")]
    [InlineData("'passwd' => 'letmein'", "'passwd' => '[REDACTED:credential-assignment]'")]
    [InlineData("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG", "AWS_SECRET_ACCESS_KEY=[REDACTED:credential-assignment]")]
    public void AnAssignedCredential_HasItsValueRedacted(string text, string expected)
    {
        Assert.Equal(expected, Redact(text).Text);
    }

    [Theory]
    [InlineData("password = get_password()")]
    [InlineData("api_key = os.environ[\"KEY\"]")]
    [InlineData("password: process.env.DB_PASSWORD")]
    [InlineData("password_hint: \"your pet's name\"")]
    [InlineData("password: \"\"")]
    [InlineData("Enter your password: below")]
    public void CodeAndPlaceholders_AreLeftAlone(string text)
    {
        Assert.True(Redact(text).Report.IsClean);
    }

    // -------------------------------------------------------------------- pii

    [Fact]
    public void PersonalData_IsLeftAloneUnlessAskedFor()
    {
        var text = $"Contact jane.doe@example.com, card {SecretSamples.CardNumber}";

        Assert.True(Redact(text).Report.IsClean);

        var redaction = Redact(text, includePii: true);

        Assert.Equal("Contact [REDACTED:email], card [REDACTED:credit-card]", redaction.Text);
        Assert.Equal([SecretScanner.Email, SecretScanner.CreditCard], redaction.Report.Detectors);
    }

    [Theory]
    [InlineData("4111-1111-1111-1111")]   // Visa, dashed
    [InlineData("5555555555554444")]      // Mastercard 5-series
    [InlineData("2223003122003222")]      // Mastercard 2-series
    [InlineData("378282246310005")]       // Amex
    [InlineData("6011111111111117")]      // Discover
    public void ACardNumber_IsRecognisedAcrossNetworksAndFormats(string number)
    {
        Assert.Equal([SecretScanner.CreditCard], Redact($"card {number}.", includePii: true).Report.Detectors);
    }

    [Theory]
    [InlineData("4111111111111112")]      // fails Luhn
    [InlineData("1727790000000")]         // a millisecond timestamp: passes no prefix
    [InlineData("2023003122003222")]      // 2-series outside Mastercard's range
    [InlineData("8111111111111111")]      // no card network
    public void DigitRunsThatAreNotCards_AreLeftAlone(string number)
    {
        Assert.True(Redact($"id {number}", includePii: true).Report.IsClean);
    }

    // ------------------------------------------------------------------ speed

    [Fact]
    public void AdversarialInput_IsScannedInLinearTime()
    {
        // Shapes that would make a backtracking engine retry at every offset:
        // near-miss keys, endless assignments, a key header with no end. The
        // non-backtracking engine reads each character a bounded number of times,
        // so a megabyte costs what a megabyte costs.
        var hostile = string.Concat(
            string.Concat(Enumerable.Repeat("password=", 20_000)),
            string.Concat(Enumerable.Repeat("AKIA", 20_000)),
            "-----BEGIN RSA PRIVATE KEY-----",
            new string('-', 50_000),
            new string('a', 200_000) + "@",
            string.Concat(Enumerable.Repeat("1 ", 50_000)));

        var stopwatch = Stopwatch.StartNew();

        SecretScanner.Redact(hostile, includePii: true);

        // Generous, so a loaded CI runner cannot fail it: catastrophic
        // backtracking on this input is minutes, not seconds.
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(10), $"took {stopwatch.Elapsed}");
    }

    // ------------------------------------------------------------------- json

    [Fact]
    public void Json_StringsAnywhereInTheTreeAreRedacted()
    {
        var element = Json($$"""
            {"env": [{"name": "AWS", "value": "{{SecretSamples.AwsAccessKey}}"}], "count": 3, "ok": true, "none": null}
            """);

        var redaction = SecretScanner.RedactJson(element, null, includePii: false);

        Assert.Equal("[REDACTED:aws-access-key]",
            redaction.Element.GetProperty("env")[0].GetProperty("value").GetString());
        Assert.Equal(3, redaction.Element.GetProperty("count").GetInt32());
        Assert.True(redaction.Element.GetProperty("ok").GetBoolean());
        Assert.Equal(JsonValueKind.Null, redaction.Element.GetProperty("none").ValueKind);
        Assert.Equal([SecretScanner.AwsAccessKey], redaction.Report.Detectors);
    }

    [Fact]
    public void Json_ACleanValueComesBackUntouched()
    {
        var element = Json("""{"path": "/tmp/notes.txt", "lines": [1, 2]}""");

        var redaction = SecretScanner.RedactJson(element, null, includePii: false);

        Assert.True(redaction.Report.IsClean);
        Assert.Equal(element.GetRawText(), redaction.Element.GetRawText());
    }

    [Theory]
    [InlineData("password")]
    [InlineData("clientSecret")]
    [InlineData("X-Api-Key")]
    [InlineData("Authorization")]
    public void Json_ASensitiveKeyHidesItsWholeValue(string key)
    {
        // A human-chosen password has no shape to match. Its label is the only
        // evidence, and the whole value goes, not just a recognisable part.
        var element = Json($$"""{"{{key}}": "correct horse battery staple"}""");

        var redaction = SecretScanner.RedactJson(element, null, includePii: false);

        Assert.Equal("[REDACTED:sensitive-field]", redaction.Element.GetProperty(key).GetString());
        Assert.Equal([SecretScanner.SensitiveField], redaction.Report.Detectors);
    }

    [Fact]
    public void Json_ArrayItemsInheritTheirKey()
    {
        var element = Json("""{"cookie": ["one", "two"]}""");

        var redaction = SecretScanner.RedactJson(element, null, includePii: false);

        Assert.All(
            redaction.Element.GetProperty("cookie").EnumerateArray(),
            item => Assert.Equal("[REDACTED:sensitive-field]", item.GetString()));
        Assert.Equal(2, redaction.Report.Count);
    }

    [Fact]
    public void Json_TheCallersPropertyNameCounts()
    {
        // How a tool argument arrives: the key is in the dictionary, the value is
        // the element.
        var redaction = SecretScanner.RedactJson(Json("\"hunter2\""), "password", includePii: false);

        Assert.Equal("[REDACTED:sensitive-field]", redaction.Element.GetString());
    }

    [Fact]
    public void Json_AnUnnamedStringIsScannedForShapes()
    {
        // A bare string at the root has no key to judge it by, so only a
        // recognisable credential is taken.
        Assert.True(SecretScanner.RedactJson(Json("\"hunter2\""), null, includePii: false).Report.IsClean);
        Assert.Equal(
            "[REDACTED:jwt]",
            SecretScanner.RedactJson(Json($"\"{SecretSamples.Jwt}\""), null, includePii: false).Element.GetString());
    }

    [Fact]
    public void Json_AnEmptySensitiveValueIsLeftAlone()
    {
        Assert.True(SecretScanner.RedactJson(Json("\"\""), "password", includePii: false).Report.IsClean);
    }

    [Fact]
    public void Json_ABareTokenKeyIsNotSensitive()
    {
        // Pagination cursors are called "token" too, and redacting one breaks the
        // next page.
        var element = Json("""{"token": "page-2-cursor", "max_tokens": "4096"}""");

        Assert.True(SecretScanner.RedactJson(element, null, includePii: false).Report.IsClean);
    }

    [Fact]
    public void Json_KeysAreNeverRewritten()
    {
        var element = Json($$"""{"{{SecretSamples.AwsAccessKey}}": 1}""");

        Assert.True(SecretScanner.RedactJson(element, null, includePii: false).Report.IsClean);
    }

    // ----------------------------------------------------------------- report

    [Fact]
    public void Report_MergeKeepsOrderDeduplicatesAndSumsCounts()
    {
        var first = new SecretReport([SecretScanner.Jwt, SecretScanner.Email], 2);
        var second = new SecretReport([SecretScanner.Email, SecretScanner.StripeKey], 3);

        var merged = first.Merge(second);

        Assert.Equal([SecretScanner.Jwt, SecretScanner.Email, SecretScanner.StripeKey], merged.Detectors);
        Assert.Equal(5, merged.Count);
        Assert.Equal("jwt, email, stripe-key", merged.Summary);
    }

    [Fact]
    public void Report_MergingWithCleanReturnsTheOtherSide()
    {
        var found = new SecretReport([SecretScanner.Jwt], 1);

        Assert.Same(found, found.Merge(SecretReport.Clean));
        Assert.Same(found, SecretReport.Clean.Merge(found));
        Assert.Throws<ArgumentNullException>(() => found.Merge(null!));
    }

    [Fact]
    public void Marker_NamesTheDetector()
    {
        Assert.Equal("[REDACTED:jwt]", SecretScanner.Marker(SecretScanner.Jwt));
    }
}
