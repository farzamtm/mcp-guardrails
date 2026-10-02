using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Scanners;

namespace McpGuardrails.Core.Tests.Scanners;

/// <summary>
/// The YAML surface of the scanners section: what an operator actually writes,
/// and what happens when they write nothing at all.
/// </summary>
public sealed class ScannerPolicyLoadingTests
{
    [Fact]
    public void AFileWithNoScanners_StillScans()
    {
        // The deliberate asymmetry with budgets: an omitted cap means no cap, but
        // an omitted scanner means the default one, and the default is on. A
        // guardrail that has to be switched on protects nobody, and annotating a
        // result cannot break a call.
        var document = PolicyLoader.Parse("""
            rules:
              - name: allow-all
                decision: allow
            """);

        Assert.Null(document.Scanners);
        Assert.Equal(ScanAction.Annotate, document.EffectiveScanners.EffectiveInjection.EffectiveAction);
        Assert.False(document.EffectiveScanners.EffectiveInjection.IsOff);
    }

    [Fact]
    public void NoPolicyFileAtAll_StillScans()
    {
        Assert.Equal(
            ScanAction.Annotate,
            PolicyDocument.Empty.EffectiveScanners.EffectiveInjection.EffectiveAction);
    }

    [Fact]
    public void AFileWithScannersButNoRules_Loads()
    {
        var document = PolicyLoader.Parse("""
            scanners:
              injection:
                action: block
            """);

        Assert.Empty(document.EffectiveRules);
        Assert.Equal(ScanAction.Block, document.EffectiveScanners.EffectiveInjection.EffectiveAction);
    }

    [Fact]
    public void ScanningCanBeTurnedOff()
    {
        var document = PolicyLoader.Parse("""
            scanners:
              injection:
                action: off
            """);

        Assert.True(document.EffectiveScanners.EffectiveInjection.IsOff);
    }

    [Fact]
    public void AnEmptyInjectionBlock_KeepsTheDefault()
    {
        var document = PolicyLoader.Parse("""
            scanners:
              injection: {}
            """);

        Assert.NotNull(document.Scanners?.Injection);
        Assert.Null(document.Scanners?.Injection?.Action);
        Assert.Equal(ScanAction.Annotate, document.EffectiveScanners.EffectiveInjection.EffectiveAction);
    }

    [Fact]
    public void AnUnknownAction_IsRejectedWhenTheFileLoads()
    {
        var error = Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            scanners:
              injection:
                action: shout
            """));

        Assert.Contains("not valid", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnknownActionReachingValidation_NamesTheChoices()
    {
        // The JSON binder rejects an unknown string before validation ever runs,
        // so this is the belt to that braces: a value constructed in code, or a
        // future binder that is more permissive, still fails closed with a
        // message that says what is allowed.
        var policy = new ScannerPolicy { Injection = new ScannerSettings { Action = (ScanAction)99 } };

        var error = Assert.Throws<PolicyException>(policy.Validate);

        Assert.Contains("annotate, block or off", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SecretRedaction_IsOnWithNoPolicyFile()
    {
        // Arguments reach the server but not the log; results are scrubbed before
        // the model sees them; personal data is left alone until asked for.
        var secrets = PolicyDocument.Empty.EffectiveScanners.EffectiveSecrets;

        Assert.Equal(SecretArgumentAction.RedactAudit, secrets.EffectiveArguments);
        Assert.Equal(SecretResultAction.Redact, secrets.EffectiveResults);
        Assert.False(secrets.IncludePii);
    }

    [Fact]
    public void SecretRedaction_IsConfiguredPerDirection()
    {
        var document = PolicyLoader.Parse("""
            scanners:
              secrets:
                arguments: block
                results: redact
                pii: true
            """);

        var secrets = document.EffectiveScanners.EffectiveSecrets;

        Assert.Equal(SecretArgumentAction.Block, secrets.EffectiveArguments);
        Assert.Equal(SecretResultAction.Redact, secrets.EffectiveResults);
        Assert.True(secrets.IncludePii);
    }

    [Theory]
    [InlineData("redact_audit", SecretArgumentAction.RedactAudit)]
    [InlineData("redact", SecretArgumentAction.Redact)]
    [InlineData("off", SecretArgumentAction.Off)]
    public void SecretArgumentActions_UseTheirSnakeCaseNames(string yaml, SecretArgumentAction expected)
    {
        var document = PolicyLoader.Parse($"""
            scanners:
              secrets:
                arguments: {yaml}
                results: off
            """);

        Assert.Equal(expected, document.EffectiveScanners.EffectiveSecrets.EffectiveArguments);
        Assert.Equal(SecretResultAction.Off, document.EffectiveScanners.EffectiveSecrets.EffectiveResults);
    }

    [Fact]
    public void AnEmptySecretsBlock_KeepsTheDefaults()
    {
        var document = PolicyLoader.Parse("""
            scanners:
              secrets: {}
            """);

        Assert.NotNull(document.Scanners?.Secrets);
        Assert.Equal(SecretArgumentAction.RedactAudit, document.EffectiveScanners.EffectiveSecrets.EffectiveArguments);
    }

    [Fact]
    public void AnUnknownSecretAction_IsRejectedWhenTheFileLoads()
    {
        Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            scanners:
              secrets:
                results: shout
            """));
    }

    [Fact]
    public void AnUnknownSecretActionReachingValidation_NamesTheChoices()
    {
        var arguments = new ScannerPolicy
        {
            Secrets = new SecretScannerSettings { Arguments = (SecretArgumentAction)99 },
        };
        var results = new ScannerPolicy
        {
            Secrets = new SecretScannerSettings { Results = (SecretResultAction)99 },
        };

        Assert.Contains(
            "redact_audit, redact, block or off",
            Assert.Throws<PolicyException>(arguments.Validate).Message,
            StringComparison.Ordinal);
        Assert.Contains(
            "'scanners.secrets.results'",
            Assert.Throws<PolicyException>(results.Validate).Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void TheDefaults_AreAnnotateAndOn()
    {
        Assert.Equal(ScanAction.Annotate, ScannerPolicy.Default.EffectiveInjection.EffectiveAction);
        Assert.False(ScannerSettings.Default.IsOff);
        Assert.True(ScannerSettings.Disabled.IsOff);
        Assert.Equal(SecretArgumentAction.Off, SecretScannerSettings.Disabled.EffectiveArguments);
        Assert.Equal(SecretResultAction.Off, SecretScannerSettings.Disabled.EffectiveResults);
    }
}
