using System.Text.Json.Serialization;
using McpGuardrails.Core.Pins;

namespace McpGuardrails.Core.Serialization;

/// <summary>
/// Source-generated serializers for the pins file.
/// </summary>
/// <remarks>
/// Separate from <see cref="GuardrailsJsonContext"/> because the options differ:
/// the audit log is one record per line, while the pins file is indented so that
/// a change to one tool is a one-line diff in review.
/// </remarks>
[JsonSourceGenerationOptions(
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(PinsDocument))]
internal sealed partial class PinsJsonContext : JsonSerializerContext;
