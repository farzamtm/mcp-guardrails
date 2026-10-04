using System.Text.Json.Serialization;
using McpGuardrails.Core.Access;

namespace McpGuardrails.Core.Serialization;

/// <summary>
/// Source-generated serializers for the OAuth documents: the authorization
/// server metadata the proxy reads and the resource metadata it serves.
/// </summary>
/// <remarks>
/// Kept apart from <see cref="GuardrailsJsonContext"/> so the OAuth surface -
/// the two documents exchanged with authorization servers and clients - can be
/// read in one place. The <c>access:</c> policy section itself is registered
/// with the rest of the policy in <see cref="GuardrailsJsonContext"/>.
/// </remarks>
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(AuthorizationServerDocument))]
[JsonSerializable(typeof(ProtectedResourceDocument))]
internal sealed partial class AccessJsonContext : JsonSerializerContext;
