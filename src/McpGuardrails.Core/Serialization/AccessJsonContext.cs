using System.Text.Json.Serialization;
using McpGuardrails.Core.Access;

namespace McpGuardrails.Core.Serialization;

/// <summary>
/// Source-generated serializers for the OAuth documents: the authorization
/// server metadata the proxy reads and the resource metadata it serves.
/// </summary>
/// <remarks>
/// Separate from <see cref="GuardrailsJsonContext"/> because these are wire
/// formats defined by RFCs, not files an operator writes.
/// </remarks>
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(AuthorizationServerDocument))]
[JsonSerializable(typeof(ProtectedResourceDocument))]
internal sealed partial class AccessJsonContext : JsonSerializerContext;
