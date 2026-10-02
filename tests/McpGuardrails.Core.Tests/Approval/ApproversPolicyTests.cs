using System.Text;
using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Approval;

public sealed class ApproversPolicyTests
{
    private static WebhookApproverSettings Webhook(
        string? url = "https://approvals.example.com/hooks/guardrails",
        string? secretEnv = "GUARDRAILS_WEBHOOK_SECRET",
        bool? allowInsecureLocalhost = null) => new()
        {
            Url = url,
            SecretEnv = secretEnv,
            AllowInsecureLocalhost = allowInsecureLocalhost,
        };

    private static PolicyRule WebhookRule(string name = "approve-deletes") => new()
    {
        Name = name,
        Decision = Verdict.RequireApproval,
        Approval = new ApprovalSettings { Mode = ApprovalMode.Webhook },
    };

    private static PolicyException Rejects(WebhookApproverSettings webhook) =>
        Assert.Throws<PolicyException>(
            () => new ApproversPolicy { Webhook = webhook }.Validate([]));

    // --------------------------------------------------------- the section

    [Fact]
    public void NoApprovers_IsFine_WhenNoRuleNeedsOne()
    {
        ApproversPolicy.None.Validate(
        [
            new PolicyRule { Name = "in-band", Decision = Verdict.RequireApproval },
            new PolicyRule { Name = "plain", Decision = Verdict.Allow },
        ]);
    }

    [Fact]
    public void AWebhookRuleWithNoEndpoint_FailsNamingTheRule()
    {
        // Otherwise every call it matched would be denied at runtime with
        // "the approval channel is broken" - true, and no help to anyone.
        var error = Assert.Throws<PolicyException>(
            () => ApproversPolicy.None.Validate([WebhookRule("approve-deletes")]));

        Assert.Contains("approve-deletes", error.Message, StringComparison.Ordinal);
        Assert.Contains("approvers.webhook", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AWebhookRuleWithAnEndpoint_IsFine()
    {
        new ApproversPolicy { Webhook = Webhook() }.Validate([WebhookRule()]);
    }

    [Fact]
    public void TheRuleList_IsRequired()
    {
        Assert.Throws<ArgumentNullException>(() => ApproversPolicy.None.Validate(null!));
    }

    // -------------------------------------------------------------- the url

    [Theory]
    [InlineData(null)]
    [InlineData("  ")]
    public void AMissingUrl_IsRejected(string? url)
    {
        Assert.Contains("'url'", Rejects(Webhook(url: url)).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ARelativeUrl_IsRejected()
    {
        Assert.Contains(
            "not an absolute URL",
            Rejects(Webhook(url: "approvals.example.com/hook")).Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void CredentialsInTheUrl_AreRejected()
    {
        // A secret in the policy file by another name.
        var error = Rejects(Webhook(url: "https://user:hunter2@approvals.example.com/hook"));

        Assert.Contains("credentials", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PlainHttp_IsRejectedByDefault()
    {
        Assert.Contains(
            "allow_insecure_localhost",
            Rejects(Webhook(url: "http://approvals.example.com/hook")).Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void PlainHttp_IsRejectedEvenWithTheFlagWhenNotLoopback()
    {
        // The flag's name says localhost, and it means it: an approval answered
        // over a network in the clear can be answered by whoever is on the path.
        var error = Rejects(Webhook(url: "http://approvals.example.com/hook", allowInsecureLocalhost: true));

        Assert.Contains("only permits loopback", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://localhost:8080/approve")]
    [InlineData("http://127.0.0.1:8080/approve")]
    [InlineData("http://[::1]:8080/approve")]
    public void PlainHttpToLoopback_IsAllowedWithTheFlag(string url)
    {
        var webhook = Webhook(url: url, allowInsecureLocalhost: true);

        new ApproversPolicy { Webhook = webhook }.Validate([]);

        Assert.Equal(new Uri(url), webhook.Endpoint);
    }

    [Fact]
    public void PlainHttpToLoopback_IsStillRejectedWithoutTheFlag()
    {
        Rejects(Webhook(url: "http://localhost:8080/approve", allowInsecureLocalhost: false));
    }

    [Fact]
    public void AnotherScheme_IsRejected()
    {
        Assert.Contains(
            "'ftp'",
            Rejects(Webhook(url: "ftp://approvals.example.com/hook")).Message,
            StringComparison.Ordinal);
    }

    // ------------------------------------------------------- the secret name

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void AMissingSecretEnv_IsRejected(string? name)
    {
        Assert.Contains(
            "Unsigned approval requests are not supported",
            Rejects(Webhook(secretEnv: name)).Message,
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("whsec_9f8a-7b6c+5d4e/3f2a==")]
    [InlineData("1SECRET")]
    [InlineData("MY SECRET")]
    public void ASecretEnvThatIsNotAVariableName_IsRejected(string name)
    {
        // Mostly this catches the secret itself pasted where its name belongs.
        var error = Rejects(Webhook(secretEnv: name));

        Assert.Contains("not the secret itself", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(name, error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("GUARDRAILS_WEBHOOK_SECRET")]
    [InlineData("_private")]
    [InlineData("s3cret_2")]
    public void AVariableName_IsAccepted(string name)
    {
        new ApproversPolicy { Webhook = Webhook(secretEnv: name) }.Validate([]);
    }

    // --------------------------------------------------- reading the secret

    [Fact]
    public void TheSecret_IsReadFromTheNamedVariable()
    {
        string? asked = null;

        var secret = Webhook().ReadSecret(name =>
        {
            asked = name;
            return "s3cr3t";
        });

        Assert.Equal("GUARDRAILS_WEBHOOK_SECRET", asked);
        Assert.Equal(Encoding.UTF8.GetBytes("s3cr3t"), secret);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void AnUnsetSecret_IsFatal(string? value)
    {
        // Signing with an empty key produces a signature anyone can forge.
        var error = Assert.Throws<PolicyException>(() => Webhook().ReadSecret(_ => value));

        Assert.Contains("GUARDRAILS_WEBHOOK_SECRET", error.Message, StringComparison.Ordinal);
        Assert.Contains("not set", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ReadingTheSecret_NeedsAnEnvironment()
    {
        Assert.Throws<ArgumentNullException>(() => Webhook().ReadSecret(null!));
    }
}
