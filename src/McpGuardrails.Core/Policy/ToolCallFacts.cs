using System.Text.Json;

namespace McpGuardrails.Core.Policy;

/// <summary>
/// The facts about a tool call that rules are matched against.
/// </summary>
/// <param name="ToolName">Client-visible name, e.g. <c>fs__write_file</c>.</param>
/// <param name="Arguments">Arguments supplied by the model, if any.</param>
/// <param name="Annotations">
/// Behaviour hints the downstream server published for the tool, or null when it
/// published none.
/// </param>
/// <remarks>
/// Deliberately a plain data snapshot rather than the live MCP request: it keeps
/// the evaluator free of any protocol types, which is what makes it trivially
/// unit-testable. <c>Pipeline/PolicyFacts</c> is the one place that knows how to
/// build this from an SDK request.
/// </remarks>
public sealed record ToolCallFacts(
    string ToolName,
    IReadOnlyDictionary<string, JsonElement>? Arguments = null,
    ToolAnnotationFacts? Annotations = null)
{
    /// <summary>The tool's hints, or the defaults when it declared none.</summary>
    public ToolAnnotationFacts EffectiveAnnotations => Annotations ?? ToolAnnotationFacts.Undeclared;
}

/// <summary>
/// What a downstream server says a tool does, as raw hints.
/// </summary>
/// <remarks>
/// Every hint is a <c>bool?</c> because "the server did not say" is genuinely
/// different from "the server said false", and the defaults for the two differ.
/// The <c>Is*</c> properties apply the MCP specification's defaults; policy
/// matches against those rather than the raw values.
///
/// <b>These are hints from an upstream server, and the MCP specification is
/// explicit that they are not trustworthy for security decisions.</b> A rule that
/// denies on <c>destructiveHint: true</c> is a useful blanket over tools you have
/// not enumerated; it is not a guarantee, because a hostile server can simply
/// declare its delete tool read-only. Name the tools you care about explicitly
/// and keep annotation rules as the safety net underneath.
/// </remarks>
public sealed record ToolAnnotationFacts(
    bool? ReadOnlyHint = null,
    bool? DestructiveHint = null,
    bool? IdempotentHint = null,
    bool? OpenWorldHint = null)
{
    /// <summary>A tool that declared no hints at all.</summary>
    public static ToolAnnotationFacts Undeclared { get; } = new();

    /// <summary>Read-only, defaulting to false when undeclared.</summary>
    public bool IsReadOnly => ReadOnlyHint ?? false;

    /// <summary>
    /// Destructive, defaulting to true when undeclared.
    /// </summary>
    /// <remarks>
    /// Two defaults from the MCP specification, both worth stating because both
    /// are load-bearing for safety: an undeclared tool counts as destructive, and
    /// a read-only tool never does. So a rule requiring approval for destructive
    /// tools also covers every tool that never bothered to describe itself, which
    /// is the fail-closed direction.
    /// </remarks>
    public bool IsDestructive => !IsReadOnly && (DestructiveHint ?? true);

    /// <summary>Idempotent, defaulting to false when undeclared.</summary>
    public bool IsIdempotent => IdempotentHint ?? false;

    /// <summary>Interacts with the outside world, defaulting to true.</summary>
    public bool IsOpenWorld => OpenWorldHint ?? true;
}
