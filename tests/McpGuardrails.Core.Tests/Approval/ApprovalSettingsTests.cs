using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Approval;

public sealed class ApprovalSettingsTests
{
    // ------------------------------------------------------------- defaults

    [Fact]
    public void ABareRequireApprovalRule_AsksTheClientAndWaitsFiveMinutes()
    {
        var settings = ApprovalSettings.Default;

        Assert.Equal(ApprovalMode.InBand, settings.EffectiveMode);
        Assert.Equal(TimeSpan.FromSeconds(300), settings.EffectiveTimeout);
        Assert.Equal(Verdict.Deny, settings.EffectiveOnTimeout);
        Assert.Null(settings.Prompt);

        settings.Validate("approve-destructive");
    }

    [Fact]
    public void ExplicitValues_WinOverTheDefaults()
    {
        var settings = new ApprovalSettings
        {
            Mode = ApprovalMode.InBand,
            TimeoutSeconds = 30,
            OnTimeout = Verdict.Allow,
        };

        Assert.Equal(TimeSpan.FromSeconds(30), settings.EffectiveTimeout);
        Assert.Equal(Verdict.Allow, settings.EffectiveOnTimeout);

        settings.Validate("r");
    }

    // ----------------------------------------------------------- validation

    [Fact]
    public void Slack_IsRejectedRatherThanIgnored()
    {
        // Same honesty as budgets.daily. An operator who writes 'mode: slack'
        // believes Slack is being asked; nothing notifies Slack, so the call
        // would silently fall through to whatever the in-band path decided.
        var error = Assert.Throws<PolicyException>(() =>
            new ApprovalSettings { Mode = ApprovalMode.Slack }.Validate("approve-destructive"));

        Assert.Contains("slack", error.Message, StringComparison.Ordinal);
        Assert.Contains("not implemented yet", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Webhook_IsAccepted()
    {
        // Whether an endpoint is configured for it is the document's question,
        // answered by ApproversPolicy; a rule on its own cannot know.
        var settings = new ApprovalSettings { Mode = ApprovalMode.Webhook };

        settings.Validate("approve-destructive");

        Assert.Equal(ApprovalMode.Webhook, settings.EffectiveMode);
    }

    [Fact]
    public void AnUnknownMode_IsRejected()
    {
        var error = Assert.Throws<PolicyException>(
            () => new ApprovalSettings { Mode = (ApprovalMode)99 }.Validate("r"));

        Assert.Contains("unknown approval mode", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-30)]
    public void ATimeoutThatGivesNobodyTimeToAnswer_IsRejected(int seconds)
    {
        var error = Assert.Throws<PolicyException>(
            () => new ApprovalSettings { TimeoutSeconds = seconds }.Validate("r"));

        Assert.Contains("timeout_s", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnOnTimeoutOfRequireApproval_IsRejected()
    {
        // It would mean asking again, forever.
        var error = Assert.Throws<PolicyException>(() =>
            new ApprovalSettings { OnTimeout = Verdict.RequireApproval }.Validate("r"));

        Assert.Contains("on_timeout", error.Message, StringComparison.Ordinal);
        Assert.Contains("Use allow or deny", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ModeNames_AreTheOnesUsedInThePolicyFile()
    {
        Assert.Equal("in_band", ApprovalSettings.Describe(ApprovalMode.InBand));
        Assert.Equal("slack", ApprovalSettings.Describe(ApprovalMode.Slack));
        Assert.Equal("webhook", ApprovalSettings.Describe(ApprovalMode.Webhook));
    }
}
