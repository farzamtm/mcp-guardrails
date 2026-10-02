using McpGuardrails.Core.Approval;

namespace McpGuardrails.Core.Tests.Approval;

public sealed class ApprovalChannelRouterTests
{
    private sealed class Answers(ApprovalOutcome outcome) : IApprovalChannel
    {
        public int Asked { get; private set; }

        public ValueTask<ApprovalOutcome> RequestAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken)
        {
            Asked++;
            return ValueTask.FromResult(outcome);
        }
    }

    private static ApprovalRequest Request(ApprovalMode mode) =>
        new("fs__delete", "approve-deletes", "Delete?") { Mode = mode };

    [Fact]
    public async Task InBand_GoesToTheClient()
    {
        var inBand = new Answers(ApprovalOutcome.Approved);
        var webhook = new Answers(ApprovalOutcome.Declined);
        var router = new ApprovalChannelRouter(inBand, webhook);

        var outcome = await router.RequestAsync(Request(ApprovalMode.InBand), CancellationToken.None);

        Assert.Equal(ApprovalOutcome.Approved, outcome);
        Assert.Equal((1, 0), (inBand.Asked, webhook.Asked));
    }

    [Fact]
    public async Task Webhook_GoesToTheWebhook()
    {
        var inBand = new Answers(ApprovalOutcome.Approved);
        var webhook = new Answers(ApprovalOutcome.Declined);
        var router = new ApprovalChannelRouter(inBand, webhook);

        var outcome = await router.RequestAsync(Request(ApprovalMode.Webhook), CancellationToken.None);

        Assert.Equal(ApprovalOutcome.Declined, outcome);
        Assert.Equal((0, 1), (inBand.Asked, webhook.Asked));
    }

    [Theory]
    [InlineData(ApprovalMode.Webhook)]
    [InlineData(ApprovalMode.Slack)]
    [InlineData((ApprovalMode)99)]
    public async Task AModeWithNoChannel_FailsInsteadOfAskingTheClient(ApprovalMode mode)
    {
        // An operator routes a rule out of band because nobody is at the client;
        // quietly asking the client instead would put the question to no one,
        // or worse, to the agent's own automation.
        var inBand = new Answers(ApprovalOutcome.Approved);
        var router = new ApprovalChannelRouter(inBand);

        var outcome = await router.RequestAsync(Request(mode), CancellationToken.None);

        Assert.Equal(ApprovalOutcome.Failed, outcome);
        Assert.Equal(0, inBand.Asked);
    }

    [Fact]
    public async Task Arguments_AreRequired()
    {
        Assert.Throws<ArgumentNullException>(() => new ApprovalChannelRouter(null!));

        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await new ApprovalChannelRouter(new Answers(ApprovalOutcome.Approved))
                .RequestAsync(null!, CancellationToken.None));
    }
}
