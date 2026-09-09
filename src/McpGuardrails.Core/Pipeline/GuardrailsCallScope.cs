using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Pipeline;

/// <summary>
/// Per-call state shared between filters in the pipeline.
/// </summary>
/// <remarks>
/// The problem this solves: the audit filter is the OUTERMOST layer, but the
/// decision it needs to record is made by the policy filter INSIDE it. The MCP
/// SDK's RequestContext has no general-purpose items bag to pass data through,
/// so the pipeline needs its own channel.
///
/// The AsyncLocal gotcha, which is the whole reason this class exists:
///
///     AsyncLocal values flow DOWN into nested async calls, never back UP.
///     If the inner filter assigned to the AsyncLocal directly, the outer
///     filter would still observe null when its `finally` ran.
///
/// So the outer scope publishes a mutable HOLDER once, and inner filters mutate
/// the holder's contents rather than the AsyncLocal itself. Mutating shared state
/// propagates in both directions; reassigning the AsyncLocal does not.
///
/// Each call gets its own holder, so concurrent tool calls cannot see each
/// other's decisions.
/// </remarks>
public sealed class GuardrailsCallScope : IDisposable
{
    private static readonly AsyncLocal<GuardrailsCallScope?> _currentScope = new();

    private GuardrailsCallScope()
    {
    }

    /// <summary>The scope for the call currently executing, if any.</summary>
    public static GuardrailsCallScope? Current => _currentScope.Value;

    /// <summary>The policy decision recorded for this call, if one was reached.</summary>
    public Decision? Decision { get; private set; }

    /// <summary>Opens a scope for one tool call. Dispose at the end of the call.</summary>
    public static GuardrailsCallScope Begin()
    {
        var scope = new GuardrailsCallScope();
        _currentScope.Value = scope;
        return scope;
    }

    /// <summary>
    /// Records the policy decision for the call in progress.
    /// </summary>
    /// <remarks>
    /// A no-op when there is no active scope, so the policy filter stays usable
    /// on its own (in tests, or if audit is ever disabled) rather than throwing.
    /// </remarks>
    public static void RecordDecision(Decision decision)
    {
        ArgumentNullException.ThrowIfNull(decision);

        if (_currentScope.Value is { } scope)
        {
            scope.Decision = decision;
        }
    }

    public void Dispose() => _currentScope.Value = null;
}
