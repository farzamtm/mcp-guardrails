namespace McpGuardrails.Core.Approval;

/// <summary>
/// Sends each question to the channel its rule asked for.
/// </summary>
/// <remarks>
/// The mode is per rule, but the gate takes one channel, and it should stay that
/// way: the gate owns deadlines and verdicts, and knowing which transport serves
/// which mode is a composition concern. So the composition root hands the gate
/// this, and the gate never learns there is more than one way to ask.
/// </remarks>
public sealed class ApprovalChannelRouter : IApprovalChannel
{
    private readonly IApprovalChannel _inBand;
    private readonly IApprovalChannel? _webhook;

    /// <param name="inBand">Asks the human at the MCP client.</param>
    /// <param name="webhook">Asks the configured HTTP endpoint, when there is one.</param>
    public ApprovalChannelRouter(IApprovalChannel inBand, IApprovalChannel? webhook = null)
    {
        ArgumentNullException.ThrowIfNull(inBand);

        _inBand = inBand;
        _webhook = webhook;
    }

    /// <inheritdoc />
    public ValueTask<ApprovalOutcome> RequestAsync(
        ApprovalRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var channel = request.Mode switch
        {
            ApprovalMode.InBand => _inBand,
            ApprovalMode.Webhook => _webhook,
            _ => null,
        };

        // Policy validation should make this unreachable - a webhook rule needs
        // an approvers.webhook section and any other mode fails to parse. If it
        // is reached anyway, the answer is a denial, and specifically not a
        // fallback to asking the client: an operator who routed a rule to an
        // out-of-band approver did so because nobody is at the client.
        return channel is null
            ? ValueTask.FromResult(ApprovalOutcome.Failed)
            : channel.RequestAsync(request, cancellationToken);
    }
}
