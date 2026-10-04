using System.Globalization;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Approval;

/// <summary>
/// Turns a <c>require_approval</c> verdict into a real answer from a real human.
/// </summary>
/// <remarks>
/// Runs between the policy evaluator and the budget gate, and that order is the
/// whole design: a call waiting on a human has not been forwarded, so it must not
/// spend budget, and an approved call must be charged before it goes out. Budget
/// already refuses to charge anything blocked, so approving a call here is what
/// makes it billable.
///
/// The gate owns the deadline rather than the channel, so every approver - the
/// client, a webhook, any channel added beside them - inherits the same semantics
/// for "nobody answered".
/// </remarks>
public static class ApprovalGate
{
    /// <summary>
    /// Asks, waits, and converts the answer into a decision.
    /// </summary>
    /// <param name="decision">The policy's verdict; returned untouched unless it asks for approval.</param>
    /// <param name="facts">The call being approved, for the generated question.</param>
    /// <param name="channel">Where to ask.</param>
    /// <param name="cancellationToken">The client's own cancellation, not the approval deadline.</param>
    public static async ValueTask<Decision> ApplyAsync(
        Decision decision,
        ToolCallFacts facts,
        IApprovalChannel channel,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(decision);
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(channel);

        if (decision.Verdict is not Verdict.RequireApproval)
        {
            return decision;
        }

        var settings = decision.Approval ?? ApprovalSettings.Default;
        var outcome = await AskAsync(decision, facts, settings, channel, cancellationToken);

        return Resolve(decision, settings, outcome);
    }

    private static async ValueTask<ApprovalOutcome> AskAsync(
        Decision decision,
        ToolCallFacts facts,
        ApprovalSettings settings,
        IApprovalChannel channel,
        CancellationToken cancellationToken)
    {
        // Linked, so the client hanging up cancels the question too - there is no
        // point holding a prompt open for a session that has gone away.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(settings.EffectiveTimeout);

        var request = new ApprovalRequest(
            facts.ToolName,
            decision.RuleName ?? "(unnamed rule)",
            Prompt(decision, facts, settings))
        {
            Mode = settings.EffectiveMode,
            Deadline = DateTimeOffset.UtcNow + settings.EffectiveTimeout,
            Server = facts.Server,
            Arguments = facts.Arguments,
        };

        try
        {
            return await channel.RequestAsync(request, deadline.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Our deadline fired, not the caller's cancellation. The distinction
            // matters: one is a policy outcome the operator configured, the other
            // is the client abandoning the call, and only the first is ours to
            // answer.
            return ApprovalOutcome.TimedOut;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A channel that throws is a broken channel, and a broken guardrail
            // is a reason to stop rather than a reason to proceed. Swallowed here
            // so the failure becomes a denial the model can read instead of an
            // exception surfacing as a transport error.
            return ApprovalOutcome.Failed;
        }
    }

    private static Decision Resolve(
        Decision decision,
        ApprovalSettings settings,
        ApprovalOutcome outcome)
    {
        var seconds = settings.EffectiveTimeout.TotalSeconds.ToString(
            "0.#",
            CultureInfo.InvariantCulture);

        return outcome switch
        {
            ApprovalOutcome.Approved => Approved(decision, outcome),

            ApprovalOutcome.Declined => Refuse(
                decision,
                outcome,
                "a human reviewed this call and declined it. Do not retry and do not work " +
                "around it; tell the user what you were trying to do and ask how they would " +
                "like to proceed."),

            ApprovalOutcome.TimedOut when settings.EffectiveOnTimeout is Verdict.Allow =>
                Approved(decision, outcome),

            ApprovalOutcome.TimedOut => Refuse(
                decision,
                outcome,
                $"nobody answered the approval request within {seconds}s, and this rule " +
                "treats silence as refusal. Tell the user the call is waiting on their " +
                "approval rather than retrying."),

            // The local UI is a process of its own; "unavailable" there means it
            // is not running, which the user can fix in a few seconds, unlike the
            // in-band case below.
            ApprovalOutcome.Unavailable when settings.EffectiveMode is ApprovalMode.LocalUi => Refuse(
                decision,
                outcome,
                "this call needs approval in the local Guardrails UI, and the UI is not " +
                "running. Do not retry on your own; tell the user to start it with " +
                "'mcp-guardrails ui', approve the call there, and ask you to try again."),

            ApprovalOutcome.Unavailable => Refuse(
                decision,
                outcome,
                // Two causes, one message: either the client lacks elicitation,
                // or the proxy is serving stateless HTTP, which has no channel
                // back to the client to put a question on.
                "this call needs human approval and your MCP client cannot ask anyone - it " +
                "does not support elicitation, or the proxy is serving it over stateless " +
                "HTTP, which cannot send it the question. Nothing you can do will change " +
                "that; tell the user, who can approve the action themselves or adjust the " +
                "policy."),

            _ => Refuse(
                decision,
                outcome,
                "the approval request could not be delivered, so the call is refused. Tell " +
                "the user that the approval channel is broken."),
        };
    }

    /// <remarks>
    /// Keeps the rule's name and cost. The call is now an ordinary allowed call -
    /// it gets charged to the budget like any other - and the audit line still
    /// says which rule sent it to a human.
    /// </remarks>
    private static Decision Approved(Decision decision, ApprovalOutcome outcome) => decision with
    {
        Verdict = Verdict.Allow,
        Reason = outcome is ApprovalOutcome.TimedOut
            ? $"Approved by default: rule '{decision.RuleName}' allows the call when the " +
              "approval request goes unanswered."
            : $"Approved by a human for rule '{decision.RuleName}'.",
        ApprovalResult = outcome,
    };

    /// <remarks>
    /// The rule name is kept, so the refusal reads "approval for rule 'x'", and
    /// the trail gets a line so <c>--explain</c> shows why a call that matched a
    /// require_approval rule ended up refused.
    /// </remarks>
    private static Decision Refuse(Decision decision, ApprovalOutcome outcome, string reason) =>
        decision.RefusedBy(
            DecisionSource.Approval,
            decision.RuleName,
            reason,
            $"approval for rule '{decision.RuleName}': {outcome.ToWireName()} -> deny") with
        {
            ApprovalResult = outcome,
        };

    /// <remarks>
    /// The rule's own prompt or the generated question, then whatever a gate
    /// noted about the call - the argument detectors' findings, say - so the
    /// warning reaches the human however the rule worded its question.
    /// </remarks>
    private static string Prompt(Decision decision, ToolCallFacts facts, ApprovalSettings settings)
    {
        var question = settings.Prompt ?? Question(decision, facts);

        return decision.ApprovalNote is { } note ? $"{question} {note}" : question;
    }

    /// <remarks>
    /// What the human reads when the rule does not supply its own prompt. It
    /// names the tool and the rule because those are the two facts an approver
    /// cannot get anywhere else in that moment - the client shows them a dialog,
    /// not the policy file.
    /// </remarks>
    private static string Question(Decision decision, ToolCallFacts facts) =>
        $"Allow the agent to call '{facts.ToolName}'? " +
        $"Guardrails rule '{decision.RuleName}' requires your approval.";
}
