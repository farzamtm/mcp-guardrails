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
/// Which guardrail produced a decision.
/// </summary>
/// <remarks>
/// Only used to word the refusal. "Blocked by guardrails policy rule 'no-writes'"
/// and "Blocked by guardrails budget 'session.max_cost'" call for different
/// actions from the agent - one means never do this, the other means not right
/// now - and a model that cannot tell them apart will either give up too early
/// or retry forever.
/// </remarks>
public enum DecisionSource
{
    /// <summary>A rule in the policy file.</summary>
    Policy,

    /// <summary>A spend or call cap.</summary>
    Budget,
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

    /// <summary>What this call costs against the budget.</summary>
    /// <remarks>
    /// Carried on the decision because the rule that matched is the thing that
    /// knows the price, and the budget gate runs after evaluation. One per call
    /// unless a rule says otherwise, so budgets are meaningful before anyone
    /// writes a single <c>cost:</c>.
    /// </remarks>
    public long Cost { get; init; } = PolicyRule.DefaultCost;

    /// <summary>Which guardrail decided this.</summary>
    public DecisionSource Source { get; init; } = DecisionSource.Policy;

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
    public string ToModelMessage() => (Source, RuleName) switch
    {
        (DecisionSource.Budget, { } limit) => $"Blocked by guardrails budget '{limit}': {Reason}",
        (_, { } rule) => $"Blocked by guardrails policy rule '{rule}': {Reason}",
        _ => $"Blocked by guardrails policy: {Reason}",
    };
}
