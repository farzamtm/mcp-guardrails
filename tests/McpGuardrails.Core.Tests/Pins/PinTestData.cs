using System.Text.Json;
using McpGuardrails.Core.Pins;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Tests.Pins;

/// <summary>Tools, subjects and pins for the pinning tests.</summary>
internal static class PinTestData
{
    public const string Identity = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    public const string OtherIdentity = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    public static readonly DateTimeOffset PinnedAt = new(2026, 10, 4, 10, 0, 0, TimeSpan.Zero);

    public static JsonElement Json(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }

    public static Tool Tool(string name, string description = "Does a thing.") => new()
    {
        Name = name,
        Description = description,
        InputSchema = Json("""{"type":"object","properties":{"path":{"type":"string"}}}"""),
    };

    public static PinSubject Subject(string server = "fs", string identity = Identity, params Tool[] tools) =>
        new(server, identity, $"{server}-command", tools);

    /// <summary>The pins a subject with these tools would get.</summary>
    public static PinnedServer Pinned(string identity = Identity, params Tool[] tools) =>
        Subject("fs", identity, tools).Pin(PinnedAt) with { IdentityHint = "fs-command" };
}
