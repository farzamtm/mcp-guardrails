using System.Text.Json.Serialization;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Approval;

/// <summary>
/// Where the approval question is asked.
/// </summary>
/// <remarks>
/// Serialized as a string so the policy file reads as prose and so adding a
/// member cannot change the meaning of an existing file - the same reasoning as
/// <see cref="Verdict"/>.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<ApprovalMode>))]
public enum ApprovalMode
{
    /// <summary>Ask the human sitting at the MCP client, over the protocol.</summary>
    [JsonStringEnumMemberName("in_band")]
    InBand,

    /// <summary>Ask a Slack channel. Not implemented yet.</summary>
    [JsonStringEnumMemberName("slack")]
    Slack,

    /// <summary>
    /// POST the question to the endpoint in <c>approvers.webhook</c> and wait for its answer.
    /// </summary>
    [JsonStringEnumMemberName("webhook")]
    Webhook,
}

/// <summary>
/// The <c>approval:</c> block of a rule.
/// </summary>
/// <remarks>
/// Only meaningful on a <c>require_approval</c> rule, and validation says so
/// rather than ignoring it: an approval block on an <c>allow</c> rule reads like
/// a gate and is not one.
/// </remarks>
public sealed record ApprovalSettings
{
    /// <summary>Default wait before the question is considered unanswered.</summary>
    /// <remarks>
    /// Five minutes: long enough that a human who stepped away for a coffee can
    /// still answer, short enough that a forgotten prompt does not wedge the
    /// agent for the rest of the session.
    /// </remarks>
    public const int DefaultTimeoutSeconds = 300;

    /// <summary>The settings used when a rule says <c>require_approval</c> and nothing else.</summary>
    public static ApprovalSettings Default { get; } = new();

    /// <summary>Where to ask, defaulting to the client.</summary>
    [JsonPropertyName("mode")]
    public ApprovalMode? Mode { get; init; }

    /// <inheritdoc cref="Mode" />
    [JsonIgnore]
    public ApprovalMode EffectiveMode => Mode ?? ApprovalMode.InBand;

    /// <summary>How long to wait for an answer, in seconds.</summary>
    [JsonPropertyName("timeout_s")]
    public int? TimeoutSeconds { get; init; }

    /// <inheritdoc cref="TimeoutSeconds" />
    [JsonIgnore]
    public TimeSpan EffectiveTimeout =>
        TimeSpan.FromSeconds(TimeoutSeconds ?? DefaultTimeoutSeconds);

    /// <summary>What an unanswered question means: <c>deny</c> or <c>allow</c>.</summary>
    /// <remarks>
    /// Defaults to deny. Silence is not consent, and the common reason for
    /// silence is that nobody was looking - which is precisely when a destructive
    /// call should not proceed.
    /// </remarks>
    [JsonPropertyName("on_timeout")]
    public Verdict? OnTimeout { get; init; }

    /// <inheritdoc cref="OnTimeout" />
    [JsonIgnore]
    public Verdict EffectiveOnTimeout => OnTimeout ?? Verdict.Deny;

    /// <summary>The question to put to the human, overriding the generated one.</summary>
    /// <remarks>
    /// Worth writing. The generated question names the tool and the rule, which
    /// is accurate but tells the approver nothing about why this rule exists.
    /// </remarks>
    [JsonPropertyName("prompt")]
    public string? Prompt { get; init; }

    internal void Validate(string ruleName)
    {
        if (!Enum.IsDefined(EffectiveMode))
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has an unknown approval mode. Use in_band or webhook.");
        }

        // The same honesty the budgets section applies to `daily:`. A Slack
        // approver needs somewhere to send the question and a way to hear the
        // answer back, neither of which exists yet - so accepting the
        // configuration would leave an operator believing Slack was being asked
        // when nothing was.
        if (EffectiveMode is ApprovalMode.Slack)
        {
            throw new PolicyException(
                $"Rule '{ruleName}' asks for '{Describe(EffectiveMode)}' approval, which is not " +
                "implemented yet. Use 'in_band' (asking the human at the MCP client) or " +
                "'webhook'; remove the mode rather than relying on an approver nobody notifies.");
        }

        if (TimeoutSeconds is <= 0)
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has a 'timeout_s' of {TimeoutSeconds}. " +
                "Give the human some time to answer, or omit it for the " +
                $"{DefaultTimeoutSeconds}s default.");
        }

        // allow and deny are the only coherent answers to "nobody replied".
        // require_approval would mean asking again forever.
        if (EffectiveOnTimeout is not (Verdict.Allow or Verdict.Deny))
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has an 'on_timeout' of " +
                $"'{PolicyEvaluator.Describe(EffectiveOnTimeout)}'. Use allow or deny.");
        }
    }

    internal static string Describe(ApprovalMode mode) => mode switch
    {
        ApprovalMode.Slack => "slack",
        ApprovalMode.Webhook => "webhook",
        _ => "in_band",
    };
}
