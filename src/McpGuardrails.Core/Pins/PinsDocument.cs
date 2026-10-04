using System.Text.Json.Serialization;

namespace McpGuardrails.Core.Pins;

/// <summary>
/// The pins file: what every server's tools looked like when they were trusted.
/// </summary>
/// <remarks>
/// A wire DTO in the same style as the policy and servers documents, and plain,
/// indented JSON with sorted keys on purpose: a team can commit it next to its
/// policy, and an upstream that changes its tools then shows up as a reviewable
/// diff of hashes rather than a binary blob changing.
///
/// Unknown keys are refused. A hand-edited file with a misspelt key would
/// otherwise load as "nothing pinned", and the next start would quietly re-pin
/// whatever the server serves now.
/// </remarks>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PinsDocument
{
    /// <summary>The only format version this build reads and writes.</summary>
    public const int CurrentVersion = 1;

    /// <summary>A file with nothing pinned yet.</summary>
    public static PinsDocument Empty { get; } = new() { Version = CurrentVersion, Servers = [] };

    /// <summary>The format version; required.</summary>
    [JsonPropertyName("version")]
    public int? Version { get; init; }

    /// <summary>Pinned servers by name.</summary>
    [JsonPropertyName("servers")]
    public SortedDictionary<string, PinnedServer>? Servers { get; init; }

    /// <summary>The servers, or none when the file omits the key.</summary>
    [JsonIgnore]
    public IReadOnlyDictionary<string, PinnedServer> EffectiveServers =>
        (IReadOnlyDictionary<string, PinnedServer>?)Servers ?? new SortedDictionary<string, PinnedServer>();

    /// <summary>This document with one server's pins replaced, or added.</summary>
    public PinsDocument With(string server, PinnedServer pins)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(pins);

        var servers = Copy();
        servers[server] = pins;
        return this with { Version = CurrentVersion, Servers = servers };
    }

    /// <summary>This document without one server's pins.</summary>
    public PinsDocument Without(string server)
    {
        ArgumentNullException.ThrowIfNull(server);

        var servers = Copy();
        servers.Remove(server);
        return this with { Version = CurrentVersion, Servers = servers };
    }

    // Copied rather than mutated, so a document the caller still holds - the one
    // a comparison was made against - never changes underneath it.
    private SortedDictionary<string, PinnedServer> Copy() =>
        new(Servers ?? new SortedDictionary<string, PinnedServer>(), StringComparer.Ordinal);
}

/// <summary>One server's pins.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PinnedServer
{
    /// <summary>
    /// A hash of what was launched or connected to; see <see cref="ServerIdentity"/>.
    /// </summary>
    [JsonPropertyName("identity")]
    public string? Identity { get; init; }

    /// <summary>
    /// What was launched, as the servers file spelled it, so a person reading a
    /// changed identity can tell which version the pins came from.
    /// </summary>
    [JsonPropertyName("identity_hint")]
    public string? IdentityHint { get; init; }

    /// <summary>When the server was pinned or last accepted.</summary>
    [JsonPropertyName("pinned_at")]
    public DateTimeOffset? PinnedAt { get; init; }

    /// <summary>Pinned tools by the name the server gives them.</summary>
    [JsonPropertyName("tools")]
    public SortedDictionary<string, PinnedTool>? Tools { get; init; }

    /// <summary>The tools, or none when the file omits the key.</summary>
    [JsonIgnore]
    public IReadOnlyDictionary<string, PinnedTool> EffectiveTools =>
        (IReadOnlyDictionary<string, PinnedTool>?)Tools ?? new SortedDictionary<string, PinnedTool>();
}

/// <summary>One pinned tool definition.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PinnedTool
{
    /// <summary>The definition's hash; see <see cref="ToolDefinition"/>.</summary>
    [JsonPropertyName("hash")]
    public string? Hash { get; init; }

    /// <summary>
    /// The canonical definition, deflate-compressed and base64-encoded, so
    /// <c>pins diff</c> can show what changed and not only that something did.
    /// </summary>
    /// <remarks>
    /// Optional: a file written by hand with only hashes still pins, and
    /// <c>pins diff</c> then says it has no copy to compare against.
    /// </remarks>
    [JsonPropertyName("definition")]
    public string? Definition { get; init; }
}
