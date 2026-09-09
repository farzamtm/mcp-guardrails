using System.Text.Json.Serialization;

namespace McpGuardrails.Core.Policy;

/// <summary>
/// What the policy engine decided to do with a tool call.
/// </summary>
/// <remarks>
/// Serialized as a string so policy files read naturally (<c>decision: deny</c>)
/// and so adding a member cannot silently change the meaning of an existing file,
/// which is exactly what would happen with the default numeric encoding.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<Verdict>))]
public enum Verdict
{
    /// <summary>Forward the call downstream.</summary>
    [JsonStringEnumMemberName("allow")]
    Allow,

    /// <summary>Refuse the call and tell the model why.</summary>
    [JsonStringEnumMemberName("deny")]
    Deny,

    /// <summary>Hold the call until a human approves it. Implemented in step 8.</summary>
    [JsonStringEnumMemberName("require_approval")]
    RequireApproval,
}

/// <summary>
/// The outcome of evaluating one tool call against the policy.
/// </summary>
/// <param name="Verdict">Allow, deny, or ask a human.</param>
/// <param name="Reason">
/// Why, written for the model to read. See <see cref="ToModelMessage"/>.
/// </param>
/// <param name="RuleName">Name of the rule that matched, or null for the default.</param>
/// <param name="Trail">
/// Every rule considered and why it did or did not match, in order. Surfaced by
/// <c>--explain</c> so "why was this blocked?" has an answer that does not
/// require reading the source.
/// </param>
/// <remarks>
/// C# notes:
/// - This is a positional record: the parameter list generates the constructor,
///   the properties, value equality and Deconstruct. Compare with the
///   property-style record in UpstreamServerConfig - both are records, the
///   positional form is just terser when every member is set at construction.
/// </remarks>
public sealed record Decision(
    Verdict Verdict,
    string Reason,
    string? RuleName = null,
    IReadOnlyList<string>? Trail = null)
{
    /// <summary>The decision used when no rule matches: allow, and say so.</summary>
    /// <remarks>
    /// Default-allow is the deliberate product choice from the spec: an empty
    /// policy file must behave as a pure passthrough with audit logging, so the
    /// proxy can be adopted before anyone writes a rule. Default-deny would be
    /// safer in the abstract and would guarantee nobody ever installs it.
    /// </remarks>
    public static Decision DefaultAllow { get; } =
        new(Verdict.Allow, "No policy rule matched; default is allow.");

    /// <summary>True when the call must not be forwarded as-is.</summary>
    public bool IsBlocked => Verdict is Verdict.Deny or Verdict.RequireApproval;

    /// <summary>
    /// Renders the denial as text for the model.
    /// </summary>
    /// <remarks>
    /// This is a prompt, not a log line, and the difference matters. An agent
    /// that reads "denied" retries the same call forever. An agent that reads
    /// "denied: exports over 100 rows need approval; try limit=100" changes
    /// approach. Denials that explain themselves turn a wall into a signpost.
    /// </remarks>
    public string ToModelMessage() => RuleName is null
        ? $"Blocked by guardrails policy: {Reason}"
        : $"Blocked by guardrails policy rule '{RuleName}': {Reason}";
}
