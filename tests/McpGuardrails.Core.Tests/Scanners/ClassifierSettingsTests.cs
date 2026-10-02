using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Scanners;

namespace McpGuardrails.Core.Tests.Scanners;

/// <summary>
/// The YAML surface of <c>scanners.injection.classifier</c>: off unless asked
/// for, on as soon as the block exists, and loud about anything malformed.
/// </summary>
public sealed class ClassifierSettingsTests
{
    private static ScannerSettings Injection(string yaml) =>
        PolicyLoader.Parse(yaml).EffectiveScanners.EffectiveInjection;

    private static PolicyException Rejects(string classifierBody) =>
        Assert.Throws<PolicyException>(() => PolicyLoader.Parse(
            "scanners:\n  injection:\n    classifier:\n" + classifierBody));

    // ---------------------------------------------------------------- defaults

    [Fact]
    public void NoClassifierBlock_MeansNoClassifier()
    {
        // The heuristics are on by default; the classifier is not. It sends tool
        // output to a third party and costs money, and neither is a default.
        Assert.Null(PolicyDocument.Empty.EffectiveScanners.EffectiveInjection.Classifier);
        Assert.False(PolicyDocument.Empty.EffectiveScanners.EffectiveInjection.UsesClassifier);
        Assert.False(Injection("scanners:\n  injection:\n    action: block\n").UsesClassifier);
    }

    [Fact]
    public void AnEmptyClassifierBlock_TurnsItOnInConfirmModeWithEveryDefault()
    {
        var settings = Injection("scanners:\n  injection:\n    classifier: {}\n");

        Assert.True(settings.UsesClassifier);

        var classifier = settings.Classifier!;
        Assert.Equal(ClassifierMode.Confirm, classifier.EffectiveMode);
        Assert.False(classifier.IsOff);
        Assert.Equal("claude-haiku-4-5-20251001", classifier.EffectiveModel);
        Assert.Equal("ANTHROPIC_API_KEY", classifier.EffectiveApiKeyEnv);
        Assert.Equal(new Uri("https://api.anthropic.com"), classifier.EffectiveBaseUrl);
        Assert.Equal(TimeSpan.FromSeconds(5), classifier.EffectiveTimeout);
        Assert.Equal(32_000, classifier.EffectiveMaxChars);
    }

    [Fact]
    public void EveryFieldCanBeSet()
    {
        var classifier = Injection("""
            scanners:
              injection:
                action: block
                classifier:
                  mode: all
                  model: claude-sonnet-5-5
                  api_key_env: MY_KEY
                  base_url: https://gateway.example.test/anthropic
                  timeout_ms: 2500
                  max_chars: 1000
            """).Classifier!;

        Assert.Equal(ClassifierMode.All, classifier.EffectiveMode);
        Assert.Equal("claude-sonnet-5-5", classifier.EffectiveModel);
        Assert.Equal("MY_KEY", classifier.EffectiveApiKeyEnv);
        Assert.Equal(new Uri("https://gateway.example.test/anthropic"), classifier.EffectiveBaseUrl);
        Assert.Equal(TimeSpan.FromMilliseconds(2500), classifier.EffectiveTimeout);
        Assert.Equal(1000, classifier.EffectiveMaxChars);
    }

    [Fact]
    public void ModeOff_KeepsTheBlockButCallsNothing()
    {
        var settings = Injection("scanners:\n  injection:\n    classifier:\n      mode: off\n");

        Assert.True(settings.Classifier!.IsOff);
        Assert.False(settings.UsesClassifier);
    }

    [Fact]
    public void ScannerOff_WinsOverAClassifierBlock()
    {
        // A classifier with no scanner around it has nothing to confirm.
        var settings = Injection("scanners:\n  injection:\n    action: off\n    classifier: {}\n");

        Assert.False(settings.UsesClassifier);
    }

    [Theory]
    [InlineData("http://localhost:8080")]
    [InlineData("http://127.0.0.1:8080/")]
    [InlineData("https://api.anthropic.com/")]
    public void SafeBaseUrls_AreAccepted(string url)
    {
        var classifier = Injection(
            $"scanners:\n  injection:\n    classifier:\n      base_url: \"{url}\"\n").Classifier!;

        Assert.Equal(new Uri(url), classifier.EffectiveBaseUrl);
    }

    // -------------------------------------------------------------- rejections

    [Fact]
    public void AnUnknownMode_IsRejectedByTheBinder()
    {
        var error = Rejects("      mode: sometimes\n");

        Assert.Contains("not valid", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnknownModeReachingValidation_NamesTheChoices()
    {
        var settings = new ScannerSettings { Classifier = new ClassifierSettings { Mode = (ClassifierMode)42 } };

        var error = Assert.Throws<PolicyException>(() => settings.Validate("injection"));

        Assert.Contains("off, confirm or all", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("      model: \"  \"\n", "'scanners.injection.classifier.model' is blank")]
    [InlineData("      api_key_env: \"\"\n", "'scanners.injection.classifier.api_key_env' is blank")]
    [InlineData("      base_url: not a url\n", "is not an absolute URL")]
    [InlineData("      base_url: http://api.anthropic.com\n", "must be https")]
    [InlineData("      base_url: ftp://localhost/\n", "must be https")]
    [InlineData("      timeout_ms: 0\n", "'scanners.injection.classifier.timeout_ms' is 0")]
    [InlineData("      timeout_ms: 60001\n", "Use 1 to 60000")]
    [InlineData("      max_chars: -1\n", "'scanners.injection.classifier.max_chars' is -1")]
    [InlineData("      max_chars: 400001\n", "Use 1 to 400000")]
    public void MalformedFields_AreRejectedWhenTheFileLoads(string body, string expected)
    {
        var error = Rejects(body);

        Assert.Contains(expected, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheBoundaryValues_AreAccepted()
    {
        var classifier = Injection(
            "scanners:\n  injection:\n    classifier:\n      timeout_ms: 60000\n      max_chars: 1\n").Classifier!;

        Assert.Equal(TimeSpan.FromMinutes(1), classifier.EffectiveTimeout);
        Assert.Equal(1, classifier.EffectiveMaxChars);
    }

    [Fact]
    public void AClassifierOnAnotherScanner_IsRejected()
    {
        // Only reachable in code today - 'scanners.secrets' is refused outright -
        // but the check must hold once another scanner section is accepted.
        var settings = new ScannerSettings { Classifier = ClassifierSettings.Default };

        var error = Assert.Throws<PolicyException>(() => settings.Validate("secrets"));

        Assert.Contains("'scanners.secrets.classifier' is not supported", error.Message, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ report

    [Theory]
    [InlineData(ClassifierOutcome.Benign, "benign")]
    [InlineData(ClassifierOutcome.Injection, "injection")]
    [InlineData(ClassifierOutcome.TimedOut, "timed_out")]
    [InlineData(ClassifierOutcome.Failed, "failed")]
    public void ReportOutcomes_AreSnakeCaseForTheAuditLog(ClassifierOutcome outcome, string expected)
    {
        Assert.Equal(expected, new ClassifierReport(outcome, Truncated: false).Describe());
    }
}
