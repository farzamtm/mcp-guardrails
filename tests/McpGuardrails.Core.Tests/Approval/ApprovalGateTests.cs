using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Approval;

public sealed class ApprovalGateTests
{
    private static readonly ToolCallFacts _call = new("fs__delete_everything");

    private static Decision NeedsApproval(
        string? rule = "approve-destructive",
        ApprovalSettings? settings = null) =>
        new(Verdict.RequireApproval, "a human must approve this", rule) { Approval = settings };

    /// <summary>A channel that answers however the test says, and records the question.</summary>
    private sealed class FakeChannel : IApprovalChannel
    {
        private readonly ApprovalOutcome _answer;
        private readonly TimeSpan _delay;
        private readonly Exception? _throws;

        public FakeChannel(
            ApprovalOutcome answer = ApprovalOutcome.Approved,
            TimeSpan delay = default,
            Exception? throws = null)
        {
            _answer = answer;
            _delay = delay;
            _throws = throws;
        }

        public ApprovalRequest? Asked { get; private set; }

        public async ValueTask<ApprovalOutcome> RequestAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken)
        {
            Asked = request;

            if (_throws is not null)
            {
                throw _throws;
            }

            // Task.Delay with the token, so the gate's deadline actually reaches
            // a waiting channel rather than being tested against a no-op.
            await Task.Delay(_delay, cancellationToken);

            return _answer;
        }
    }

    // ------------------------------------------------------------ pass-through

    [Theory]
    [InlineData(Verdict.Allow)]
    [InlineData(Verdict.Deny)]
    public async Task ADecisionThatDoesNotAskForApproval_IsUntouched(Verdict verdict)
    {
        var decision = new Decision(verdict, "already settled", "some-rule");
        var channel = new FakeChannel();

        var result = await ApprovalGate.ApplyAsync(decision, _call, channel);

        Assert.Same(decision, result);
        Assert.Null(channel.Asked);
    }

    // ----------------------------------------------------------------- answers

    [Fact]
    public async Task AHumanSayingYes_TurnsTheCallIntoAnOrdinaryAllow()
    {
        var result = await ApprovalGate.ApplyAsync(
            NeedsApproval(),
            _call,
            new FakeChannel(ApprovalOutcome.Approved));

        Assert.Equal(Verdict.Allow, result.Verdict);
        Assert.False(result.IsBlocked);
        Assert.Equal(ApprovalOutcome.Approved, result.ApprovalResult);

        // Keeps the rule, so the audit line still says which rule sent this to a
        // human, and keeps the cost, so the budget charges it like any other call.
        Assert.Equal("approve-destructive", result.RuleName);
        Assert.Contains("Approved by a human", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AHumanSayingNo_DeniesAndTellsTheAgentNotToWorkAroundIt()
    {
        var result = await ApprovalGate.ApplyAsync(
            NeedsApproval(),
            _call,
            new FakeChannel(ApprovalOutcome.Declined));

        Assert.Equal(Verdict.Deny, result.Verdict);
        Assert.Equal(DecisionSource.Approval, result.Source);
        Assert.Equal(ApprovalOutcome.Declined, result.ApprovalResult);
        Assert.Contains("declined", result.Reason, StringComparison.Ordinal);
        Assert.Contains("do not work around it", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADeclinedCall_IsWordedAsAnApprovalNotAPolicyRule()
    {
        var result = await ApprovalGate.ApplyAsync(
            NeedsApproval(),
            _call,
            new FakeChannel(ApprovalOutcome.Declined));

        Assert.StartsWith(
            "Blocked by guardrails approval for rule 'approve-destructive':",
            result.ToModelMessage(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task AClientThatCannotAsk_IsADenialThatSaysSo()
    {
        // The fail-closed case, and the one an operator is most likely to meet:
        // a client with no elicitation support turns every require_approval rule
        // into a wall. Saying why is the difference between a bug report and a
        // configuration change.
        var result = await ApprovalGate.ApplyAsync(
            NeedsApproval(),
            _call,
            new FakeChannel(ApprovalOutcome.Unavailable));

        Assert.Equal(Verdict.Deny, result.Verdict);
        Assert.Equal(ApprovalOutcome.Unavailable, result.ApprovalResult);
        Assert.Contains("cannot ask anyone", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AChannelThatThrows_DeniesRatherThanEscaping()
    {
        // A broken guardrail is a reason to stop. Letting the exception out would
        // surface as a transport error and tell the model nothing.
        var result = await ApprovalGate.ApplyAsync(
            NeedsApproval(),
            _call,
            new FakeChannel(throws: new InvalidOperationException("channel is on fire")));

        Assert.Equal(Verdict.Deny, result.Verdict);
        Assert.Equal(ApprovalOutcome.Failed, result.ApprovalResult);
        Assert.Contains("could not be delivered", result.Reason, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- deadline

    [Fact]
    public async Task NobodyAnswering_DeniesByDefault()
    {
        var settings = new ApprovalSettings { TimeoutSeconds = 1 };
        var slow = new FakeChannel(ApprovalOutcome.Approved, delay: TimeSpan.FromMinutes(5));

        var result = await ApprovalGate.ApplyAsync(NeedsApproval(settings: settings), _call, slow);

        // Silence is not consent: the usual reason nobody answered is that nobody
        // was looking, which is exactly when a destructive call should not run.
        Assert.Equal(Verdict.Deny, result.Verdict);
        Assert.Equal(ApprovalOutcome.TimedOut, result.ApprovalResult);
        Assert.Contains("nobody answered", result.Reason, StringComparison.Ordinal);
        Assert.Contains("within 1s", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NobodyAnswering_CanBeConfiguredToAllow()
    {
        var settings = new ApprovalSettings { TimeoutSeconds = 1, OnTimeout = Verdict.Allow };
        var slow = new FakeChannel(ApprovalOutcome.Approved, delay: TimeSpan.FromMinutes(5));

        var result = await ApprovalGate.ApplyAsync(NeedsApproval(settings: settings), _call, slow);

        Assert.Equal(Verdict.Allow, result.Verdict);

        // Recorded as a timeout, not as an approval. "A person said yes" and
        // "nobody answered and the rule let it through" must not look the same in
        // the audit log.
        Assert.Equal(ApprovalOutcome.TimedOut, result.ApprovalResult);
        Assert.Contains("Approved by default", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheCallerCancelling_IsNotTreatedAsATimeout()
    {
        // The client hanging up is not a policy outcome, and inventing a verdict
        // for a call nobody is waiting for would put a fiction in the audit log.
        using var caller = new CancellationTokenSource();
        var slow = new FakeChannel(ApprovalOutcome.Approved, delay: TimeSpan.FromMinutes(5));

        var pending = ApprovalGate.ApplyAsync(NeedsApproval(), _call, slow, caller.Token);

        await caller.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await pending);
    }

    // ---------------------------------------------------------- the question

    [Fact]
    public async Task TheGeneratedQuestion_NamesTheToolAndTheRule()
    {
        var channel = new FakeChannel();

        await ApprovalGate.ApplyAsync(NeedsApproval(), _call, channel);

        Assert.Equal("fs__delete_everything", channel.Asked?.Tool);
        Assert.Equal("approve-destructive", channel.Asked?.RuleName);
        Assert.Contains("fs__delete_everything", channel.Asked!.Question, StringComparison.Ordinal);
        Assert.Contains("approve-destructive", channel.Asked.Question, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARulesOwnPrompt_ReplacesTheGeneratedQuestion()
    {
        var channel = new FakeChannel();
        var settings = new ApprovalSettings { Prompt = "Delete the production bucket?" };

        await ApprovalGate.ApplyAsync(NeedsApproval(settings: settings), _call, channel);

        Assert.Equal("Delete the production bucket?", channel.Asked?.Question);
    }

    [Fact]
    public async Task AnUnnamedRule_StillProducesAnAnswerableQuestion()
    {
        var channel = new FakeChannel();

        await ApprovalGate.ApplyAsync(NeedsApproval(rule: null), _call, channel);

        Assert.Equal("(unnamed rule)", channel.Asked?.RuleName);
    }

    // ------------------------------------------------------------- arguments

    [Fact]
    public async Task TheGate_RejectsNullArguments()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await ApprovalGate.ApplyAsync(null!, _call, new FakeChannel()));

        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await ApprovalGate.ApplyAsync(NeedsApproval(), null!, new FakeChannel()));

        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await ApprovalGate.ApplyAsync(NeedsApproval(), _call, null!));
    }
}
