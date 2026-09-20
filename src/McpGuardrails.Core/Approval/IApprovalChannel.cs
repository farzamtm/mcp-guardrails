namespace McpGuardrails.Core.Approval;

/// <summary>
/// What came back when a human was asked.
/// </summary>
public enum ApprovalOutcome
{
    /// <summary>A human said yes.</summary>
    Approved,

    /// <summary>A human said no, or dismissed the question.</summary>
    Declined,

    /// <summary>Nobody answered in time.</summary>
    TimedOut,

    /// <summary>There is nobody to ask: the client cannot surface the question.</summary>
    Unavailable,

    /// <summary>The attempt to ask failed.</summary>
    Failed,
}

/// <summary>
/// One approval question.
/// </summary>
/// <param name="Tool">The tool the agent is trying to call, as the client names it.</param>
/// <param name="RuleName">The rule that demanded approval.</param>
/// <param name="Question">The text to put in front of the human.</param>
public sealed record ApprovalRequest(string Tool, string RuleName, string Question);

/// <summary>
/// Somewhere a yes/no question can be put to a human.
/// </summary>
/// <remarks>
/// The seam the spec asks for. Today there is one implementation, which asks the
/// person at the MCP client through protocol elicitation; Slack and webhook
/// approvers arrive behind this interface without the gate changing, which is
/// why the gate deals in <see cref="ApprovalOutcome"/> rather than in anything
/// shaped like a chat message.
///
/// Implementations do not enforce the timeout: they are handed a token that is
/// already cancelled when the wait is over, so every channel gets the same
/// deadline semantics instead of each inventing its own.
/// </remarks>
public interface IApprovalChannel
{
    /// <summary>Asks, and waits for the answer.</summary>
    /// <remarks>
    /// Must not throw for an ordinary "no" or for a channel that cannot ask -
    /// those are <see cref="ApprovalOutcome.Declined"/> and
    /// <see cref="ApprovalOutcome.Unavailable"/>. An exception here is a bug in
    /// the channel, and the gate treats it as a denial rather than letting it
    /// escape into the tool call.
    /// </remarks>
    ValueTask<ApprovalOutcome> RequestAsync(
        ApprovalRequest request,
        CancellationToken cancellationToken);
}
