using System.Text.Json;
using McpGuardrails.Core.Approval;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace McpGuardrails.Cli;

/// <summary>
/// Asks the human sitting at the MCP client, using protocol elicitation.
/// </summary>
/// <remarks>
/// The thin, SDK-shaped half of the approval gate; everything worth testing -
/// deadlines, outcome-to-verdict mapping, the wording of the refusals - lives in
/// <see cref="ApprovalGate"/> in Core, against the interface rather than against
/// a live client.
///
/// Elicitation rather than the Tasks extension, for now. Tasks (MRTR) is the
/// spec's preferred design and avoids holding a request open at all, but it needs
/// a task-capable client on the other end; elicitation is in the SDK already and
/// works with anything that implements the capability. The interface is the seam:
/// an MRTR channel drops in beside this one.
/// </remarks>
internal sealed class ElicitationApprovalChannel : IApprovalChannel
{
    /// <summary>The single field the human answers.</summary>
    private const string _approveField = "approve";

    private readonly McpServer _server;

    public ElicitationApprovalChannel(McpServer server)
    {
        ArgumentNullException.ThrowIfNull(server);

        _server = server;
    }

    public async ValueTask<ApprovalOutcome> RequestAsync(
        ApprovalRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Asked before trying, so a client that cannot show a prompt produces a
        // clean "nobody to ask" rather than an exception we would have to read
        // the message of. The gate turns that into a denial that says so.
        if (_server.ClientCapabilities?.Elicitation is null)
        {
            return ApprovalOutcome.Unavailable;
        }

        ElicitResult result;
        try
        {
            result = await _server.ElicitAsync(
                new ElicitRequestParams
                {
                    Message = request.Question,
                    RequestedSchema = new ElicitRequestParams.RequestSchema
                    {
                        Properties =
                        {
                            [_approveField] = new ElicitRequestParams.BooleanSchema
                            {
                                Title = "Approve",
                                Description =
                                    $"Allow '{request.Tool}' (guardrails rule " +
                                    $"'{request.RuleName}').",
                            },
                        },
                        Required = [_approveField],
                    },
                },
                cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // The gate owns the deadline and distinguishes its own timeout from
            // the client hanging up, so this has to propagate rather than be
            // flattened into an outcome here.
            throw;
        }

        // "accept" with approve=false is a real answer - the human ticked nothing
        // and submitted - and it means no. Anything other than an explicit true
        // is a refusal: consent has to be given, not merely not-withheld.
        if (!result.IsAccepted)
        {
            return ApprovalOutcome.Declined;
        }

        var approved =
            result.Content?.TryGetValue(_approveField, out var answer) is true &&
            answer.ValueKind is JsonValueKind.True;

        return approved ? ApprovalOutcome.Approved : ApprovalOutcome.Declined;
    }
}
