using System.Text.Json.Serialization;

namespace McpGuardrails.Core.Approval;

/// <summary>
/// The body POSTed to an approval webhook. Its shape is a public contract.
/// </summary>
/// <remarks>
/// snake_case and a <c>version</c> field because receivers are written by other
/// people, in other languages, against the README - a field renamed here breaks
/// someone's integration without breaking anything in this repository.
/// </remarks>
internal sealed record WebhookApprovalPayload
{
    /// <summary>The current payload version.</summary>
    public const int CurrentVersion = 1;

    [JsonPropertyName("version")]
    public int Version { get; init; } = CurrentVersion;

    [JsonPropertyName("request_id")]
    public required string RequestId { get; init; }

    [JsonPropertyName("tool")]
    public required string Tool { get; init; }

    [JsonPropertyName("server")]
    public string? Server { get; init; }

    [JsonPropertyName("rule")]
    public required string Rule { get; init; }

    [JsonPropertyName("question")]
    public required string Question { get; init; }

    [JsonPropertyName("arguments")]
    public IReadOnlyDictionary<string, string>? Arguments { get; init; }

    [JsonPropertyName("sent_at")]
    public required DateTimeOffset SentAt { get; init; }

    [JsonPropertyName("deadline")]
    public DateTimeOffset? Deadline { get; init; }
}

/// <summary>
/// What an approval webhook answers with.
/// </summary>
/// <remarks>
/// Nullable throughout because a source-generated deserializer leaves anything
/// absent as null, and absent has to be distinguishable from a real answer for
/// the channel to refuse it.
/// </remarks>
internal sealed record WebhookApprovalAnswer
{
    [JsonPropertyName("request_id")]
    public string? RequestId { get; init; }

    [JsonPropertyName("decision")]
    public string? Decision { get; init; }
}
