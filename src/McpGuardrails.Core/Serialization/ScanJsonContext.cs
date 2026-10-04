using System.Text.Json.Serialization;
using McpGuardrails.Core.Scanners;

namespace McpGuardrails.Core.Serialization;

/// <summary>
/// Source-generated serializer for <c>scan --json</c>.
/// </summary>
/// <remarks>
/// Indented, like the pins file: the report is read by people as often as by
/// tools, and two reports diff line by line.
/// </remarks>
[JsonSourceGenerationOptions(WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(ScanReport))]
public sealed partial class ScanJsonContext : JsonSerializerContext;
