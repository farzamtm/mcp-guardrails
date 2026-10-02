using McpGuardrails.Core.Approval;

namespace McpGuardrails.Cli;

/// <summary>
/// The approval channel for stateless Streamable HTTP: there is nobody to ask.
/// </summary>
/// <remarks>
/// Elicitation is a server-to-client request. In stateless mode the proxy has no
/// open stream back to the client to send it on - the SDK disables elicitation
/// outright, because the answer could arrive at a different process. Rather than
/// lean on the SDK happening to report no capability (SDK 2.2.0 does, even when
/// a 2026-07-28 client declares elicitation in the request's own metadata) and on
/// that never changing, the HTTP host says so explicitly: every
/// <c>require_approval</c> call is refused at once, with a message that names the
/// cause, instead of hanging until the deadline or failing with an exception.
///
/// Over HTTP today, a rule that needs a human should use <c>mode: webhook</c>,
/// which asks out of band and never needs the client. The Tasks/MRTR channel the
/// spec plans is the way to make in-band approval work here; it plugs into the
/// same seam.
/// </remarks>
internal sealed class StatelessHttpApprovalChannel : IApprovalChannel
{
    public static StatelessHttpApprovalChannel Instance { get; } = new();

    private StatelessHttpApprovalChannel()
    {
    }

    public ValueTask<ApprovalOutcome> RequestAsync(
        ApprovalRequest request,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult(ApprovalOutcome.Unavailable);
}
