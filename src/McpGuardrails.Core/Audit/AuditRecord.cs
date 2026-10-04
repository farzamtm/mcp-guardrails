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
    /// <remarks>
    /// Present on every per-tool event. Absent on <c>upstream_connected</c>,
    /// <c>pin_created</c> and <c>pin_reset</c>, which are about a server rather
    /// than one of its tools.
    /// </remarks>
    [JsonPropertyName("tool")]
    public string? Tool { get; init; }

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
    /// Secrets are replaced with markers before they get here, unless
    /// <c>scanners.secrets.arguments</c> is <c>off</c>. An audit log that quietly
    /// records API keys is a liability rather than a safety feature.
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
    /// True when the server returned <c>structuredContent</c> and the scanner did
    /// not pass it on.
    /// </summary>
    /// <remarks>
    /// Recorded because an annotated result is otherwise assumed to be the
    /// original plus a warning. When the structured payload was withheld, the
    /// client got the data as text only and an error flag the server never set,
    /// and someone debugging a client that broke on that needs to see why.
    /// </remarks>
    [JsonPropertyName("scanner_structured_content_withheld")]
    public bool? ScannerStructuredContentWithheld { get; init; }

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

    /// <summary>Detectors that found a secret in the arguments, e.g. aws-access-key.</summary>
    /// <remarks>
    /// Names only, for the same reason as <see cref="ScannerHits"/> and with
    /// higher stakes: the evidence here IS the secret.
    /// </remarks>
    [JsonPropertyName("argument_secrets")]
    public IReadOnlyList<string>? ArgumentSecrets { get; init; }

    /// <summary>What became of them: forwarded, redacted or blocked.</summary>
    [JsonPropertyName("argument_secrets_action")]
    public string? ArgumentSecretsAction { get; init; }

    /// <summary>Detectors that found a secret in the result.</summary>
    [JsonPropertyName("result_secrets")]
    public IReadOnlyList<string>? ResultSecrets { get; init; }

    /// <summary>What the proxy did about them: redacted or blocked.</summary>
    [JsonPropertyName("result_secrets_action")]
    public string? ResultSecretsAction { get; init; }

    /// <summary>How the proxy reaches the server: stdio, http or sse. <c>upstream_connected</c> only.</summary>
    [JsonPropertyName("transport")]
    public string? Transport { get; init; }

    /// <summary>How many tools the server advertised. <c>upstream_connected</c> and <c>pin_created</c> only.</summary>
    [JsonPropertyName("tool_count")]
    public int? ToolCount { get; init; }

    /// <summary>
    /// What was connected to, as written in the servers file: the command line
    /// or the URL, with <c>${VAR}</c> references unexpanded. <c>upstream_connected</c>,
    /// <c>pin_created</c> and, on a changed identity, <c>pin_changed</c>.
    /// </summary>
    /// <remarks>
    /// The template rather than the expanded value, so a token passed as
    /// <c>${GITHUB_TOKEN}</c> is recorded as that reference and never as itself;
    /// anything secret-shaped written into the file literally is masked too.
    /// </remarks>
    [JsonPropertyName("identity")]
    public string? Identity { get; init; }

    /// <summary>
    /// Why a tool differs from its pin: changed, added or identity_changed, on
    /// <c>pin_changed</c>; removed, on a <c>pin_accepted</c> that dropped the pin
    /// of a tool the server no longer serves.
    /// </summary>
    [JsonPropertyName("pin_change")]
    public string? PinChange { get; init; }

    [JsonPropertyName("duration_ms")]
    public required double DurationMs { get; init; }

    /// <summary>True when the tool reported failure, or the proxy refused it.</summary>
    [JsonPropertyName("is_error")]
    public required bool IsError { get; init; }

    /// <summary>Populated when the call threw rather than returning an error result.</summary>
    [JsonPropertyName("error")]
    public string? Error { get; init; }
}
