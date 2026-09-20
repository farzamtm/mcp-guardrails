using System.Text.Json.Serialization;
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
/// </remarks>
public sealed record ScannerPolicy
{
    /// <summary>Prompt-injection scanning of tool results.</summary>
    [JsonPropertyName("injection")]
    public ScannerSettings? Injection { get; init; }

    /// <summary>
    /// Secret and PII redaction. Parsed only so it can be rejected - see
    /// <see cref="Validate"/>.
    /// </summary>
    [JsonPropertyName("secrets")]
    public ScannerSettings? Secrets { get; init; }

    /// <summary>The defaults: injection scanning on, annotating what it finds.</summary>
    public static ScannerPolicy Default { get; } = new();

    /// <summary>The injection settings, or the defaults when the file omits them.</summary>
    /// <remarks>
    /// Read through here rather than off <see cref="Injection"/> for the reason
    /// documented across the policy types: property initializers are not applied
    /// by the source-generated deserializer, so "absent" has to be modelled.
    /// </remarks>
    [JsonIgnore]
    public ScannerSettings EffectiveInjection => Injection ?? ScannerSettings.Default;

    /// <summary>Validates the section, throwing with a message naming the problem.</summary>
    public void Validate()
    {
        EffectiveInjection.Validate("injection");

        // The same honesty the budgets section applies to `daily:` and approval
        // applies to `mode: slack`. Redaction is the next piece of work and the
        // key is already reserved; accepting it now would leave an operator
        // believing their API keys were being scrubbed out of the audit log when
        // nothing was scrubbing them.
        if (Secrets is not null)
        {
            throw new PolicyException(
                "'scanners.secrets' is not implemented yet: nothing redacts secrets from " +
                "arguments, results or the audit log in this build. Remove the section " +
                "rather than relying on a scrubber that does nothing.");
        }
    }
}

/// <summary>
/// Settings for one scanner.
/// </summary>
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

    internal void Validate(string scanner)
    {
        if (!Enum.IsDefined(EffectiveAction))
        {
            throw new PolicyException(
                $"'scanners.{scanner}.action' is not a known action. " +
                "Use annotate, block or off.");
        }
    }
}
