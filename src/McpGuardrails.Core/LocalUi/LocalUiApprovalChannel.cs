using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Scanners;

namespace McpGuardrails.Core.LocalUi;

/// <summary>
/// Asks in the approval inbox of the local UI, for <c>mode: local_ui</c> rules.
/// </summary>
/// <remarks>
/// <para>The wire protocol is the webhook's: one signed POST of the same payload,
/// held open until a human decides, answered with the same
/// <c>{"request_id", "decision"}</c> shape, pointed at the UI's loopback port with
/// the UI's own per-run secret instead of one from the policy. Reusing it means
/// the redaction, the correlation check, the bounded read and every fail-closed
/// rule are the ones the webhook channel already has and already tests, not a
/// second copy of them that could drift.</para>
///
/// <para>The UI is located afresh for every question (see <see cref="UiRendezvous"/>):
/// it is a separate process the user may start, stop or restart while the proxy
/// keeps running. When it cannot be found, the answer is
/// <see cref="ApprovalOutcome.Unavailable"/>, which the gate turns into a refusal
/// telling the model to have the user start it. It is never a fallback to asking
/// the client: an operator who routed a rule to the local UI did so because the
/// client cannot ask - stateless HTTP, or a client with no elicitation.</para>
/// </remarks>
public sealed class LocalUiApprovalChannel : IApprovalChannel
{
    private readonly Func<UiEndpoint?> _locate;
    private readonly SecretScannerSettings _redaction;
    private readonly Func<HttpMessageHandler> _handler;

    /// <param name="locate">Reads the rendezvous file; returns null when no UI is running.</param>
    /// <param name="redaction">The secret scanner's settings, as for the webhook channel.</param>
    /// <param name="handler">The transport; <see cref="WebhookApprovalChannel.CreateHandler"/> in production.</param>
    public LocalUiApprovalChannel(
        Func<UiEndpoint?> locate,
        SecretScannerSettings redaction,
        Func<HttpMessageHandler> handler)
    {
        ArgumentNullException.ThrowIfNull(locate);
        ArgumentNullException.ThrowIfNull(redaction);
        ArgumentNullException.ThrowIfNull(handler);

        _locate = locate;
        _redaction = redaction;
        _handler = handler;
    }

    /// <inheritdoc />
    public async ValueTask<ApprovalOutcome> RequestAsync(
        ApprovalRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (_locate() is not { } endpoint)
        {
            return ApprovalOutcome.Unavailable;
        }

        // A channel per question, not a pooled one: approvals are rare, the UI's
        // address and secret change every time it restarts, and disposing after
        // one request leaves no connection pinned to a port some other program
        // may have taken since.
        using var channel = new WebhookApprovalChannel(endpoint.ApprovalsUrl, endpoint.Secret, _handler(), _redaction);

        return await channel.RequestAsync(request, cancellationToken);
    }
}
