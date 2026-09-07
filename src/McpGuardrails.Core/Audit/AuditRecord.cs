using System.Text.Json;
using System.Text.Json.Serialization;

namespace McpGuardrails.Core.Audit;

/// <summary>
/// One line in the audit log: a single tool call, what it asked for, and how it
/// went.
/// </summary>
/// <remarks>
/// This is the artefact that makes the proxy useful before a single policy rule
/// exists. "Drop it in and see what your agent is actually doing" is the adoption
/// lever, and this record is that feature.
///
/// C# notes:
/// - [JsonPropertyName] pins the wire name. Without it, renaming a C# property
///   would silently change the log format and break everyone's downstream jq.
/// - The type is a record for value semantics and terse declaration, but note
///   that records are only shallowly immutable: the Arguments dictionary is
///   still a reference. We never mutate it after construction.
/// </remarks>
public sealed record AuditRecord
{
    [JsonPropertyName("ts")]
    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>Event discriminator, e.g. "tool_call".</summary>
    [JsonPropertyName("event")]
    public required string Event { get; init; }

    /// <summary>Client-visible tool name, e.g. "fs__write_file".</summary>
    [JsonPropertyName("tool")]
    public required string Tool { get; init; }

    /// <summary>Downstream server that served the call, when it resolved.</summary>
    [JsonPropertyName("server")]
    public string? Server { get; init; }

    /// <summary>Tool name as the downstream server knows it, e.g. "write_file".</summary>
    [JsonPropertyName("downstream_tool")]
    public string? DownstreamTool { get; init; }

    /// <summary>
    /// Arguments the client supplied.
    /// </summary>
    /// <remarks>
    /// Logged verbatim today. Step 9 adds secret/PII redaction, and this is the
    /// field it has to scrub - an audit log that quietly records API keys is a
    /// liability rather than a safety feature.
    /// </remarks>
    [JsonPropertyName("arguments")]
    public IReadOnlyDictionary<string, JsonElement>? Arguments { get; init; }

    [JsonPropertyName("duration_ms")]
    public required double DurationMs { get; init; }

    /// <summary>True when the tool reported failure, or the proxy refused it.</summary>
    [JsonPropertyName("is_error")]
    public required bool IsError { get; init; }

    /// <summary>Populated when the call threw rather than returning an error result.</summary>
    [JsonPropertyName("error")]
    public string? Error { get; init; }
}
