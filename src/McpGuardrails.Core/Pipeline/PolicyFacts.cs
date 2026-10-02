using McpGuardrails.Core.Policy;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Pipeline;

/// <summary>
/// Builds the policy engine's view of a call from the protocol's view of it.
/// </summary>
/// <remarks>
/// The one place that touches both worlds. <see cref="ToolCallFacts"/> stays free
/// of MCP types so the evaluator can be tested with plain data, and the CLI stays
/// free of mapping logic so it remains pure host wiring - which matters, because
/// the CLI is excluded from coverage and anything with a decision in it does not
/// belong there.
/// </remarks>
public static class PolicyFacts
{
    /// <summary>
    /// Snapshots one call.
    /// </summary>
    /// <param name="toolName">Client-visible, namespaced tool name.</param>
    /// <param name="request">The incoming call parameters, if the client sent any.</param>
    /// <param name="tool">
    /// The downstream tool definition, when the name resolved to one. Null for an
    /// unknown tool, which policy still gets to see: a rule denying <c>*</c> must
    /// apply to a call the proxy is about to reject anyway, or the audit log
    /// would disagree with the policy about what happened.
    /// </param>
    /// <param name="server">The owning downstream server, when the name resolved to one.</param>
    public static ToolCallFacts ForCall(
        string toolName,
        CallToolRequestParams? request,
        Tool? tool,
        string? server = null) =>
        new(toolName, request?.Arguments?.AsReadOnly(), Annotations(tool), server);

    /// <summary>Copies a tool's hints into the policy engine's own shape.</summary>
    /// <remarks>
    /// Returns null when the server declared no annotations at all, which the
    /// evaluator treats as "every hint undeclared" and therefore as the MCP
    /// defaults. Copying rather than holding the protocol object keeps the facts
    /// an immutable snapshot: the SDK's tool list is shared across calls.
    /// </remarks>
    private static ToolAnnotationFacts? Annotations(Tool? tool) =>
        tool?.Annotations is { } annotations
            ? new ToolAnnotationFacts(
                annotations.ReadOnlyHint,
                annotations.DestructiveHint,
                annotations.IdempotentHint,
                annotations.OpenWorldHint)
            : null;
}
