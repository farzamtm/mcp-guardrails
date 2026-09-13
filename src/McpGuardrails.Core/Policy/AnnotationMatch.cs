using System.Text.Json.Serialization;

namespace McpGuardrails.Core.Policy;

/// <summary>
/// Matches a tool by the behaviour it advertises rather than by its name.
/// </summary>
/// <remarks>
/// <code>
/// match:
///   annotations:
///     destructiveHint: true
/// </code>
///
/// The value of this is coverage of tools nobody enumerated: a new server added
/// next month, or a tool whose name says nothing about what it does. Every hint
/// listed must hold, and each is compared against the tool's <i>effective</i>
/// hint - see <see cref="ToolAnnotationFacts"/> for the defaults the MCP
/// specification applies when a server stays silent.
///
/// The hint names use the protocol's camelCase spelling on purpose. Policy files
/// are read next to the MCP documentation, and renaming <c>destructiveHint</c> to
/// something more C#-ish would only make that harder.
/// </remarks>
public sealed record AnnotationMatch
{
    /// <summary>Match tools that do (or do not) claim to be read-only.</summary>
    [JsonPropertyName("readOnlyHint")]
    public bool? ReadOnlyHint { get; init; }

    /// <summary>Match tools that do (or do not) count as destructive.</summary>
    [JsonPropertyName("destructiveHint")]
    public bool? DestructiveHint { get; init; }

    /// <summary>Match tools that are (or are not) safe to repeat.</summary>
    [JsonPropertyName("idempotentHint")]
    public bool? IdempotentHint { get; init; }

    /// <summary>Match tools that do (or do not) reach outside the local system.</summary>
    [JsonPropertyName("openWorldHint")]
    public bool? OpenWorldHint { get; init; }

    /// <summary>True when no hint is specified.</summary>
    [JsonIgnore]
    public bool IsEmpty =>
        ReadOnlyHint is null &&
        DestructiveHint is null &&
        IdempotentHint is null &&
        OpenWorldHint is null;

    internal void Validate(string ruleName)
    {
        if (IsEmpty)
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has an empty 'annotations' block. " +
                "Name at least one hint, or omit the block to match every tool.");
        }
    }

    internal bool Matches(ToolAnnotationFacts facts) =>
        (ReadOnlyHint is not { } readOnly || readOnly == facts.IsReadOnly) &&
        (DestructiveHint is not { } destructive || destructive == facts.IsDestructive) &&
        (IdempotentHint is not { } idempotent || idempotent == facts.IsIdempotent) &&
        (OpenWorldHint is not { } openWorld || openWorld == facts.IsOpenWorld);
}
