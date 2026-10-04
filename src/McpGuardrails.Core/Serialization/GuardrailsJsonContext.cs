using System.Text.Json;
using System.Text.Json.Serialization;
using McpGuardrails.Core.Access;
using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Audit;
using McpGuardrails.Core.Budget;
using McpGuardrails.Core.LocalUi;
using McpGuardrails.Core.Packs;
using McpGuardrails.Core.Pins;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Scanners;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Serialization;

/// <summary>
/// Source-generated JSON serializers for every type the proxy writes.
/// </summary>
/// <remarks>
/// Why this exists, and why now rather than in week 4:
///
/// The default JsonSerializer.Serialize(object) inspects types with reflection at
/// runtime. Native AOT trims unused code and cannot see through that, so
/// reflection-based serialization either breaks or silently emits empty objects
/// in a published binary.
///
/// A JsonSerializerContext makes the compiler emit real, statically analysable
/// serialization code at build time. You then serialize against a typed handle -
/// GuardrailsJsonContext.Default.AuditRecord - instead of a Type.
///
/// Adding it up front costs nothing. Retrofitting it later, once every type
/// assumes reflection works, is the painful path.
///
/// C# notes:
/// - `partial` means the compiler generates the other half of this class. The
///   source generator fills in the serialization logic behind these attributes.
/// - The class body is `;` - a file-scoped empty body. There is nothing to write
///   by hand.
/// </remarks>
[JsonSourceGenerationOptions(
    // JSONL is machine-read; keep each record on exactly one line.
    WriteIndented = false,
    // Omit nulls so the log stays narrow and greppable.
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(AuditRecord))]
[JsonSerializable(typeof(IReadOnlyDictionary<string, JsonElement>))]
[JsonSerializable(typeof(IReadOnlyList<string>))]
// Policy types are deserialized from the YAML-derived JsonNode tree. Registering
// them here is what keeps policy loading working under Native AOT; without it,
// trimming would leave the binder unable to see these properties and every rule
// would silently load as empty.
[JsonSerializable(typeof(PolicyDocument))]
[JsonSerializable(typeof(PolicyRule))]
[JsonSerializable(typeof(PolicyMatch))]
[JsonSerializable(typeof(AnnotationMatch))]
[JsonSerializable(typeof(ArgumentPredicate))]
[JsonSerializable(typeof(IReadOnlyList<ArgumentPredicate>))]
[JsonSerializable(typeof(Verdict))]
[JsonSerializable(typeof(BudgetPolicy))]
[JsonSerializable(typeof(BudgetLimits))]
[JsonSerializable(typeof(ApprovalSettings))]
[JsonSerializable(typeof(ApprovalMode))]
[JsonSerializable(typeof(ApproversPolicy))]
[JsonSerializable(typeof(WebhookApproverSettings))]
// The webhook approval wire format, both directions. Registered here for the
// same reason as everything else: a reflection-serialized request would go out
// as "{}" from an AOT binary, and the receiver would be asked about nothing.
[JsonSerializable(typeof(WebhookApprovalPayload))]
[JsonSerializable(typeof(WebhookApprovalAnswer))]
[JsonSerializable(typeof(ScannerPolicy))]
[JsonSerializable(typeof(ScannerSettings))]
[JsonSerializable(typeof(ScanAction))]
[JsonSerializable(typeof(SecretScannerSettings))]
[JsonSerializable(typeof(SecretArgumentAction))]
[JsonSerializable(typeof(SecretResultAction))]
[JsonSerializable(typeof(ClassifierSettings))]
[JsonSerializable(typeof(ClassifierMode))]
[JsonSerializable(typeof(ArgumentScannerSettings))]
[JsonSerializable(typeof(ArgumentOverride))]
[JsonSerializable(typeof(ArgumentAction))]
[JsonSerializable(typeof(PinSettings))]
[JsonSerializable(typeof(PinMode))]
[JsonSerializable(typeof(NewToolAction))]
[JsonSerializable(typeof(AccessPolicy))]
[JsonSerializable(typeof(OAuthSettings))]
// The servers file, bound the same way as the policy. Unknown keys are refused
// per type with [JsonUnmappedMemberHandling] on the records themselves, because
// a misspelt option in the file that decides what the proxy launches must not be
// skipped quietly.
[JsonSerializable(typeof(ServerDefaultsDocument))]
[JsonSerializable(typeof(ServerEntryDocument))]
[JsonSerializable(typeof(ServerExtensionsDocument))]
[JsonSerializable(typeof(UpstreamOAuthDocument))]
[JsonSerializable(typeof(ServerIsolationDocument))]
[JsonSerializable(typeof(ContainerMountDocument))]
// Packs and policy test files, refusing unknown keys for the same reason: a
// misspelt 'expect:' would leave a test case asserting nothing.
[JsonSerializable(typeof(PackHeader))]
[JsonSerializable(typeof(PolicyTestDocument))]
[JsonSerializable(typeof(PolicyTestTool))]
[JsonSerializable(typeof(PolicyTestCase))]
// Where the local UI listens, read by every proxy with a local_ui rule.
[JsonSerializable(typeof(UiRendezvousDocument))]
internal sealed partial class GuardrailsJsonContext : JsonSerializerContext;
