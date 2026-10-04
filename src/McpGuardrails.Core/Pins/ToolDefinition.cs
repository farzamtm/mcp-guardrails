using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using McpGuardrails.Core.Serialization;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Pins;

/// <summary>
/// The part of a tool definition that is pinned, and its hash.
/// </summary>
/// <remarks>
/// Everything the model reads or the client validates against: the name, title
/// and description, both schemas and the annotations - the last because a tool
/// that quietly stops being <c>readOnlyHint: true</c> is exactly the kind of
/// change a pin is for, and policy matches on it.
///
/// Icons and <c>_meta</c> are left out. They change for cosmetic or
/// implementation reasons, the model does not read them as instructions, and
/// every change they caused would be an alarm about nothing.
/// </remarks>
public static class ToolDefinition
{
    private static readonly string[] _pinnedFields =
        ["name", "title", "description", "inputSchema", "outputSchema", "annotations"];

    /// <summary>The pinned fields of <paramref name="tool"/>, as canonical JSON.</summary>
    public static string Canonical(Tool tool) => CanonicalJson.Serialize(Pinned(tool));

    /// <summary>The hash a pin records for <paramref name="tool"/>.</summary>
    public static string Hash(Tool tool) => CanonicalJson.HashText(Canonical(tool));

    /// <summary>
    /// The pinned fields as a JSON object, read off the tool's own wire form.
    /// </summary>
    /// <remarks>
    /// Serialized with the SDK's options rather than rebuilt field by field, so
    /// the hash covers exactly what the server sent on the wire - annotation
    /// hints the SDK adds later included - and a field name can never drift from
    /// the protocol's spelling.
    /// </remarks>
    private static JsonElement Pinned(Tool tool)
    {
        ArgumentNullException.ThrowIfNull(tool);

        var wire = JsonSerializer.SerializeToElement(
            tool, (JsonTypeInfo<Tool>)McpJsonUtilities.DefaultOptions.GetTypeInfo(typeof(Tool)));

        var buffer = new System.Buffers.ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            foreach (var field in _pinnedFields)
            {
                if (wire.TryGetProperty(field, out var value) && value.ValueKind is not JsonValueKind.Null)
                {
                    writer.WritePropertyName(field);
                    value.WriteTo(writer);
                }
            }

            writer.WriteEndObject();
        }

        using var document = JsonDocument.Parse(buffer.WrittenMemory);
        return document.RootElement.Clone();
    }
}
