using System.Text.Json.Serialization;
using McpGuardrails.Core.Pins;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Scanners;

/// <summary>
/// What to do with a tool result that matched a scanner.
/// </summary>
/// <remarks>
/// Serialized as a string, like <see cref="Verdict"/>, so the policy file reads
/// as prose and adding a member cannot change the meaning of an existing file.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<ScanAction>))]
public enum ScanAction
{
    /// <summary>
    /// Forward the result, wrapped in a warning that tells the model to treat it
    /// as data.
    /// </summary>
    /// <remarks>
    /// The zero value, and that is deliberate here in a way it was not for
    /// <see cref="Verdict"/>. An omitted <c>decision:</c> defaulting to the
    /// enum's zero value was a fail-open bug precisely because Allow sat there;
    /// the safe default for a scanner is the one that keeps working, so the zero
    /// value and the safe value are the same.
    /// </remarks>
    [JsonStringEnumMemberName("annotate")]
    Annotate,

    /// <summary>Withhold the result and return a tool error instead.</summary>
    [JsonStringEnumMemberName("block")]
    Block,

    /// <summary>Do not scan at all.</summary>
    [JsonStringEnumMemberName("off")]
    Off,
}

/// <summary>
/// The <c>scanners:</c> section of a policy file.
/// </summary>
/// <remarks>
/// Policy, budget and approval all answer questions about the call going OUT.
/// This section is the first one about what comes BACK, which is why it is a
/// sibling of <c>rules:</c> rather than a field on one: a rule identifies a call,
/// and the content a server returns is not something the call's name, annotations
/// or arguments can predict.
///
/// Secret redaction lives here too even though half of it reads arguments on the
/// way out. It is still content inspection rather than call identification: a
/// rule can say "this tool, with this path", but not "any string, anywhere in
/// the call, that happens to be an access key".
/// </remarks>
public sealed record ScannerPolicy
{
    /// <summary>Prompt-injection scanning of tool results.</summary>
    [JsonPropertyName("injection")]
    public ScannerSettings? Injection { get; init; }

    /// <summary>Secret and PII redaction of arguments and results.</summary>
    [JsonPropertyName("secrets")]
    public SecretScannerSettings? Secrets { get; init; }

    /// <summary>Built-in detection of attack shapes in tool-call arguments.</summary>
    [JsonPropertyName("arguments")]
    public ArgumentScannerSettings? Arguments { get; init; }

    /// <summary>Pinning of tool definitions across restarts.</summary>
    [JsonPropertyName("pins")]
    public PinSettings? Pins { get; init; }

    /// <summary>
    /// The defaults: injection scanning annotating what it finds, and secrets
    /// redacted from the audit log and from results.
    /// </summary>
    public static ScannerPolicy Default { get; } = new();

    /// <summary>The injection settings, or the defaults when the file omits them.</summary>
    /// <remarks>
    /// Read through here rather than off <see cref="Injection"/> for the reason
    /// documented across the policy types: property initializers are not applied
    /// by the source-generated deserializer, so "absent" has to be modelled.
    /// </remarks>
    [JsonIgnore]
    public ScannerSettings EffectiveInjection => Injection ?? ScannerSettings.Default;

    /// <summary>The secret settings, or the defaults when the file omits them.</summary>
    [JsonIgnore]
    public SecretScannerSettings EffectiveSecrets => Secrets ?? SecretScannerSettings.Default;

    /// <summary>The argument detector settings, or the defaults when the file omits them.</summary>
    [JsonIgnore]
    public ArgumentScannerSettings EffectiveArguments => Arguments ?? ArgumentScannerSettings.Default;

    /// <summary>The pin settings, or the defaults when the file omits them.</summary>
    [JsonIgnore]
    public PinSettings EffectivePins => Pins ?? PinSettings.Default;

    /// <summary>Validates the section, throwing with a message naming the problem.</summary>
    public void Validate()
    {
        EffectiveInjection.Validate();
        EffectiveSecrets.Validate();
        EffectiveArguments.Validate();
        EffectivePins.Validate();
    }
}

/// <summary>
/// Settings for the injection scanner.
/// </summary>
/// <remarks>
/// Only <c>scanners.injection</c> uses this shape; secrets have their own
/// <see cref="SecretScannerSettings"/>, so the metadata and classifier keys
/// cannot appear anywhere they would be ignored.
/// </remarks>
public sealed record ScannerSettings
{
    /// <summary>The settings used when the policy file says nothing.</summary>
    public static ScannerSettings Default { get; } = new();

    /// <summary>Scanning off entirely.</summary>
    public static ScannerSettings Disabled { get; } = new() { Action = ScanAction.Off };

    /// <summary>What to do on a match: <c>annotate</c>, <c>block</c> or <c>off</c>.</summary>
    /// <remarks>
    /// Defaults to annotate, and note what that means: <b>the scanner is on for
    /// everyone, including a proxy with no policy file at all.</b> That is a
    /// considered break with "no policy means pure passthrough", because the two
    /// costs are not comparable. A missed injection is the attack this component
    /// exists to catch; a false positive is a paragraph of warning text wrapped
    /// around a result the model still receives in full. A guardrail nobody
    /// switches on catches nothing, and this one cannot break a workflow.
    ///
    /// <c>block</c> is available and is the right setting for a server whose
    /// output is meant to be structured data rather than prose. It fails the call
    /// on a heuristic match, so it will occasionally refuse a legitimate result.
    /// </remarks>
    [JsonPropertyName("action")]
    public ScanAction? Action { get; init; }

    /// <inheritdoc cref="Action" />
    [JsonIgnore]
    public ScanAction EffectiveAction => Action ?? ScanAction.Annotate;

    /// <summary>True when this scanner should not run at all.</summary>
    [JsonIgnore]
    public bool IsOff => EffectiveAction is ScanAction.Off;

    /// <summary>
    /// What to do with a tool whose metadata matches: <c>annotate</c>, <c>block</c>
    /// or <c>off</c>. Absent means the same as <see cref="Action"/>.
    /// </summary>
    /// <remarks>
    /// Tool descriptions and schemas from <c>tools/list</c> are text the model
    /// reads as part of its instructions, so they get the same heuristics as a
    /// result. They get their own setting because the trade-off differs. A
    /// result is fresh on every call; metadata is read once at startup and does
    /// not change, so a false positive is deterministic, shows up in the log
    /// before the first call, and stays. <c>block</c> here hides a tool for the
    /// life of the process - stricter than refusing one result, and more
    /// predictable. An operator can therefore want <c>block</c> for metadata and
    /// <c>annotate</c> for results, or the reverse to keep a falsely flagged tool
    /// usable without weakening result scanning.
    ///
    /// Explicit beats inherited, including against <c>action: off</c>: a value
    /// written here is a statement about metadata, and silently ignoring it
    /// because the result scanner is off would be the surprising reading.
    /// </remarks>
    [JsonPropertyName("metadata")]
    public ScanAction? Metadata { get; init; }

    /// <inheritdoc cref="Metadata" />
    [JsonIgnore]
    public ScanAction EffectiveMetadataAction => Metadata ?? EffectiveAction;

    /// <summary>
    /// The optional LLM second stage. Absent means no classifier: the heuristics
    /// alone decide, and nothing leaves the machine.
    /// </summary>
    [JsonPropertyName("classifier")]
    public ClassifierSettings? Classifier { get; init; }

    /// <summary>True when the classifier should be consulted.</summary>
    /// <remarks>
    /// <c>action: off</c> wins over a classifier block: off means the scanner does
    /// not run, and a classifier with no scanner around it has nothing to confirm.
    /// </remarks>
    [JsonIgnore]
    public bool UsesClassifier => !IsOff && Classifier is { IsOff: false };

    internal void Validate()
    {
        if (!Enum.IsDefined(EffectiveAction))
        {
            throw new PolicyException(
                "'scanners.injection.action' is not a known action. Use annotate, block or off.");
        }

        if (Metadata is { } metadata && !Enum.IsDefined(metadata))
        {
            throw new PolicyException(
                "'scanners.injection.metadata' is not a known action. Use annotate, block or off.");
        }

        Classifier?.Validate();
    }
}

/// <summary>
/// What to do with tool-call arguments that contain a secret.
/// </summary>
/// <remarks>
/// A separate enum from <see cref="SecretResultAction"/> because arguments have
/// a choice results do not: the secret can go to the server while staying out of
/// the proxy's own log. A result has only one reader, the model, so there is
/// nothing to split.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<SecretArgumentAction>))]
public enum SecretArgumentAction
{
    /// <summary>
    /// Forward the arguments unchanged, and redact them in the audit log.
    /// </summary>
    /// <remarks>
    /// The zero value and the default, because it is the one setting that cannot
    /// break a call: the server receives exactly what the model sent. What it
    /// removes is the proxy's own liability - a log of every argument ever sent is
    /// otherwise a file full of API keys that nobody thinks of as sensitive.
    /// </remarks>
    [JsonStringEnumMemberName("redact_audit")]
    RedactAudit,

    /// <summary>Replace secrets with markers in the call that is forwarded, too.</summary>
    [JsonStringEnumMemberName("redact")]
    Redact,

    /// <summary>Refuse the call. Nothing is forwarded.</summary>
    [JsonStringEnumMemberName("block")]
    Block,

    /// <summary>Do not scan arguments; log them verbatim.</summary>
    [JsonStringEnumMemberName("off")]
    Off,
}

/// <summary>
/// What to do with a tool result that contains a secret.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<SecretResultAction>))]
public enum SecretResultAction
{
    /// <summary>Replace each secret with a marker naming what was removed.</summary>
    [JsonStringEnumMemberName("redact")]
    Redact,

    /// <summary>Withhold the whole result and return a tool error.</summary>
    [JsonStringEnumMemberName("block")]
    Block,

    /// <summary>Do not scan results.</summary>
    [JsonStringEnumMemberName("off")]
    Off,
}

/// <summary>
/// The <c>scanners.secrets</c> section: redaction of credentials and personal data.
/// </summary>
/// <remarks>
/// Its own shape rather than a <see cref="ScannerSettings"/>, because the two
/// directions want different answers. An argument is the model sending a secret
/// OUT to a server; a result is a server handing one IN to the model, and from
/// there to the model provider and every transcript. One <c>action:</c> for both
/// would force an operator to pick the same trade-off for two different risks.
/// </remarks>
public sealed record SecretScannerSettings
{
    /// <summary>The settings used when the policy file says nothing.</summary>
    public static SecretScannerSettings Default { get; } = new();

    /// <summary>Both directions off.</summary>
    public static SecretScannerSettings Disabled { get; } = new()
    {
        Arguments = SecretArgumentAction.Off,
        Results = SecretResultAction.Off,
    };

    /// <summary>
    /// What to do with secrets in arguments: <c>redact_audit</c>, <c>redact</c>,
    /// <c>block</c> or <c>off</c>.
    /// </summary>
    [JsonPropertyName("arguments")]
    public SecretArgumentAction? Arguments { get; init; }

    /// <inheritdoc cref="Arguments" />
    [JsonIgnore]
    public SecretArgumentAction EffectiveArguments => Arguments ?? SecretArgumentAction.RedactAudit;

    /// <summary>What to do with secrets in results: <c>redact</c>, <c>block</c> or <c>off</c>.</summary>
    /// <remarks>
    /// Defaults to redact, which - like injection scanning - means it is on with
    /// no policy file at all. The costs are lopsided in the same direction: a key
    /// the model has read has already been sent to the model provider and cannot
    /// be unsent, while a false positive costs a marker where a token-shaped
    /// string used to be. The trailer the gate appends tells the model the markers
    /// are not the real values, which is what should stop one being written back
    /// into the file it came from.
    /// </remarks>
    [JsonPropertyName("results")]
    public SecretResultAction? Results { get; init; }

    /// <inheritdoc cref="Results" />
    [JsonIgnore]
    public SecretResultAction EffectiveResults => Results ?? SecretResultAction.Redact;

    /// <summary>Also redact personal data: email addresses and card numbers.</summary>
    /// <remarks>
    /// Off by default, the opposite call to the one made for credentials. An
    /// access key in a tool result is almost never the point of the call; an
    /// email address very often is - a git log, a contact lookup, a ticket
    /// assignee. Redacting those by default would break ordinary work to protect
    /// data the user usually asked for.
    /// </remarks>
    [JsonPropertyName("pii")]
    public bool? Pii { get; init; }

    /// <inheritdoc cref="Pii" />
    [JsonIgnore]
    public bool IncludePii => Pii ?? false;

    internal void Validate()
    {
        if (!Enum.IsDefined(EffectiveArguments))
        {
            throw new PolicyException(
                "'scanners.secrets.arguments' is not a known action. " +
                "Use redact_audit, redact, block or off.");
        }

        if (!Enum.IsDefined(EffectiveResults))
        {
            throw new PolicyException(
                "'scanners.secrets.results' is not a known action. Use redact, block or off.");
        }
    }
}
