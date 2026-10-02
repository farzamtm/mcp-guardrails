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
    /// Logged verbatim today. Secret/PII redaction is the next piece of work and
    /// this is the field it has to scrub - an audit log that quietly records API
    /// keys is a liability rather than a safety feature.
    /// </remarks>
    [JsonPropertyName("arguments")]
    public IReadOnlyDictionary<string, JsonElement>? Arguments { get; init; }

    /// <summary>Policy verdict for this call: allow, deny or require_approval.</summary>
    /// <remarks>
    /// Recorded as a string rather than the enum's numeric value so the log stays
    /// readable and greppable without a lookup table.
    /// </remarks>
    [JsonPropertyName("decision")]
    public string? Decision { get; init; }

    /// <summary>Name of the policy rule that decided, if any matched.</summary>
    [JsonPropertyName("rule")]
    public string? Rule { get; init; }

    /// <summary>Why the policy decided as it did.</summary>
    [JsonPropertyName("decision_reason")]
    public string? DecisionReason { get; init; }

    /// <summary>What the human said, when one was asked: approved, declined, timed_out…</summary>
    /// <remarks>
    /// Separate from <see cref="Decision"/> because the verdict alone loses the
    /// part an auditor cares about. "allow" covers both "a person looked at this
    /// and said yes" and "nobody answered and the rule let it through", and those
    /// are not the same event.
    /// </remarks>
    [JsonPropertyName("approval")]
    public string? Approval { get; init; }

    /// <summary>
    /// Heuristics the result scanner matched, when the call returned something.
    /// </summary>
    /// <remarks>
    /// Absent means one of two things and the difference is visible from the rest
    /// of the line: a refused call never produced a result to scan, and a
    /// forwarded call that says nothing here came back clean.
    ///
    /// Names only, never the matched text. The evidence is attacker-controlled
    /// content, and a log somebody greps - or pipes into another model - is not
    /// where it should be replayed.
    /// </remarks>
    [JsonPropertyName("scanner_hits")]
    public IReadOnlyList<string>? ScannerHits { get; init; }

    /// <summary>What the proxy did about them: annotated or blocked.</summary>
    [JsonPropertyName("scanner_action")]
    public string? ScannerAction { get; init; }

    /// <summary>
    /// What the LLM classifier said, when it was consulted: injection, benign,
    /// timed_out or failed.
    /// </summary>
    /// <remarks>
    /// Recorded even when it changed nothing, because "the classifier failed and
    /// the heuristics decided" and "the classifier agreed" are different events
    /// that produce identical results. The verdict only, never the text either
    /// side saw or wrote.
    /// </remarks>
    [JsonPropertyName("classifier")]
    public string? Classifier { get; init; }

    /// <summary>True when the result was longer than the classifier was shown.</summary>
    [JsonPropertyName("classifier_truncated")]
    public bool? ClassifierTruncated { get; init; }

    /// <summary>Why the classifier failed, when it did: an HTTP status, a timeout, a bad reply.</summary>
    [JsonPropertyName("classifier_error")]
    public string? ClassifierError { get; init; }

    [JsonPropertyName("duration_ms")]
    public required double DurationMs { get; init; }

    /// <summary>True when the tool reported failure, or the proxy refused it.</summary>
    [JsonPropertyName("is_error")]
    public required bool IsError { get; init; }

    /// <summary>Populated when the call threw rather than returning an error result.</summary>
    [JsonPropertyName("error")]
    public string? Error { get; init; }
}
