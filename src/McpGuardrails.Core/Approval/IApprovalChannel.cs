using System.Text.Json;

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
/// <remarks>
/// The positional three are what any approver needs. The rest is context an
/// out-of-band approver cannot get any other way - a person reading a webhook
/// notification is not looking at the agent's conversation - and an in-band one
/// is free to ignore.
/// </remarks>
public sealed record ApprovalRequest(string Tool, string RuleName, string Question)
{
    /// <summary>Which channel the rule asked for.</summary>
    public ApprovalMode Mode { get; init; } = ApprovalMode.InBand;

    /// <summary>Unique per question, so an answer can be matched to what was asked.</summary>
    public string RequestId { get; init; } = Guid.NewGuid().ToString("N");

    /// <summary>When the gate stops waiting, for an approver to show the human.</summary>
    public DateTimeOffset? Deadline { get; init; }

    /// <summary>The downstream server that owns the tool, when it resolved to one.</summary>
    public string? Server { get; init; }

    /// <summary>The arguments the model sent, if any.</summary>
    public IReadOnlyDictionary<string, JsonElement>? Arguments { get; init; }
}

/// <summary>
/// Somewhere a yes/no question can be put to a human.
/// </summary>
/// <remarks>
/// The seam the spec asks for. Two implementations today - the person at the MCP
/// client through protocol elicitation, and an HTTP endpoint
/// (<see cref="WebhookApprovalChannel"/>) - with <see cref="ApprovalChannelRouter"/>
/// choosing between them per rule. A Slack approver arrives behind this interface
/// without the gate changing, which is why the gate deals in
/// <see cref="ApprovalOutcome"/> rather than in anything shaped like a chat message.
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
