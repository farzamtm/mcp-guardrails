using McpGuardrails.Core.Scanners;

namespace McpGuardrails.Core.Tests.Scanners;

/// <summary>
/// The classifier is a third party: what reaches it must already be redacted.
/// </summary>
public sealed class RedactingInjectionClassifierTests
{
    /// <summary>Records what it was handed and answers with a fixed verdict.</summary>
    private sealed class RecordingClassifier : IInjectionClassifier
    {
        public string? Seen { get; private set; }

        public CancellationToken Token { get; private set; }

        public ValueTask<ClassifierVerdict> ClassifyAsync(string text, CancellationToken cancellationToken)
        {
            Seen = text;
            Token = cancellationToken;

            return ValueTask.FromResult(ClassifierVerdict.Injection);
        }
    }

    [Fact]
    public async Task Secrets_are_redacted_before_the_inner_classifier_sees_them()
    {
        var inner = new RecordingClassifier();
        var classifier = new RedactingInjectionClassifier(inner, includePii: false);

        var verdict = await classifier.ClassifyAsync($"key={SecretSamples.AwsAccessKey}", CancellationToken.None);

        Assert.Equal(ClassifierVerdict.Injection, verdict);
        Assert.DoesNotContain(SecretSamples.AwsAccessKey, inner.Seen);
        Assert.Contains(SecretScanner.Marker("aws-access-key"), inner.Seen);
    }

    [Fact]
    public async Task Pii_is_redacted_only_when_asked()
    {
        var text = $"card {SecretSamples.CardNumber}";
        var without = new RecordingClassifier();
        var with = new RecordingClassifier();

        await new RedactingInjectionClassifier(without, includePii: false).ClassifyAsync(text, CancellationToken.None);
        await new RedactingInjectionClassifier(with, includePii: true).ClassifyAsync(text, CancellationToken.None);

        Assert.Equal(text, without.Seen);
        Assert.DoesNotContain(SecretSamples.CardNumber, with.Seen);
    }

    [Fact]
    public async Task The_cancellation_token_is_passed_through()
    {
        using var cts = new CancellationTokenSource();
        var inner = new RecordingClassifier();

        await new RedactingInjectionClassifier(inner, includePii: false).ClassifyAsync("clean", cts.Token);

        Assert.Equal(cts.Token, inner.Token);
        Assert.Equal("clean", inner.Seen);
    }

    [Fact]
    public void A_null_inner_classifier_is_rejected() =>
        Assert.Throws<ArgumentNullException>(() => new RedactingInjectionClassifier(null!, includePii: false));
}
