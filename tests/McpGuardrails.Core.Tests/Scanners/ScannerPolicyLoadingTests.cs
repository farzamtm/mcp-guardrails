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
    public void AskingForSecretRedaction_IsAnErrorRatherThanASilentNoOp()
    {
        // Same honesty as 'budgets.daily' and 'approval.mode: slack'. Nothing
        // redacts anything yet, and an operator who believes their API keys are
        // being scrubbed is worse off than one who gets an error at startup.
        var error = Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            scanners:
              secrets:
                action: block
            """));

        Assert.Contains("'scanners.secrets' is not implemented yet", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheDefaults_AreAnnotateAndOn()
    {
        Assert.Equal(ScanAction.Annotate, ScannerPolicy.Default.EffectiveInjection.EffectiveAction);
        Assert.False(ScannerSettings.Default.IsOff);
        Assert.True(ScannerSettings.Disabled.IsOff);
    }
}
