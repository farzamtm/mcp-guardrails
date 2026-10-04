using System.Text.Json.Serialization;
using McpGuardrails.Core.Scanners;

namespace McpGuardrails.Core.Serialization;

/// <summary>
/// Source-generated serializer for <c>scan --json</c>.
/// </summary>
/// <remarks>
/// Indented, like the pins file: the report is read by people as often as by
/// tools, and two reports diff line by line. Its own context rather than the
/// pins file's because the two formats version independently, and internal:
/// callers go through <see cref="ScanReport.ToJson"/>, so the format is produced
/// in one place, under the coverage gate.
/// </remarks>
[JsonSourceGenerationOptions(WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(ScanReport))]
internal sealed partial class ScanJsonContext : JsonSerializerContext;
