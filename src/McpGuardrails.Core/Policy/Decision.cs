using System.Text.Json.Serialization;
using McpGuardrails.Core.Approval;

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

    /// <summary>Hold the call until a human approves it; see ApprovalGate.</summary>
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

    /// <summary>A human, or the absence of one.</summary>
    Approval,

    /// <summary>
    /// A content scanner: a secret or an attack shape in the arguments, or a tool
    /// whose definition was withheld for looking like an injection.
    /// </summary>
    Scanner,
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
    /// Default-allow is a deliberate product choice: an empty
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

    /// <summary>
    /// How to ask for approval, when the verdict is <see cref="Verdict.RequireApproval"/>.
    /// </summary>
    /// <remarks>
    /// Carried from the matched rule for the same reason as <see cref="Cost"/>:
    /// the rule knows, and the gate that needs it runs later. Null on any other
    /// verdict, and on a require_approval rule that configured nothing.
    /// </remarks>
    public ApprovalSettings? Approval { get; init; }

    /// <summary>
    /// What the human said, once one has been asked.
    /// </summary>
    /// <remarks>
    /// Recorded rather than inferred from the verdict, because "allowed" and
    /// "allowed because nobody answered and the rule permits that" are very
    /// different lines to find in an audit log six weeks later.
    /// </remarks>
    public ApprovalOutcome? ApprovalResult { get; init; }

    /// <summary>
    /// A sentence appended to the question an approver is asked, when a gate
    /// found something they should know before answering.
    /// </summary>
    /// <remarks>
    /// Set by the argument detectors under <c>action: approve</c>. Appended
    /// rather than replacing the question, so a rule's own <c>prompt:</c> is
    /// still what the human reads first.
    /// </remarks>
    public string? ApprovalNote { get; init; }

    /// <summary>
    /// This decision, overturned into a refusal by a later gate.
    /// </summary>
    /// <param name="source">The gate refusing.</param>
    /// <param name="rule">The rule, budget limit or scanner it refused under.</param>
    /// <param name="reason">Why, written for the model.</param>
    /// <param name="trailEntry">
    /// The line <c>--explain</c> shows for the refusal. Appended only when a
    /// trail is being kept, so a call without <c>--explain</c> allocates nothing.
    /// </param>
    /// <remarks>
    /// Every gate after the policy refuses through here rather than building a
    /// decision by hand, because the hand-built copies drifted: one dropped the
    /// approval result, so a call a human approved and the budget then refused
    /// lost the approval from the audit log and the approvals counter; another
    /// left the trail empty, so <c>--explain</c> showed nothing for an approval
    /// refusal. Built with <c>with</c>, so whatever an earlier gate recorded -
    /// cost, approval settings, the human's answer - survives by default, and a
    /// property added later survives too without anyone remembering to copy it.
    /// </remarks>
    public Decision RefusedBy(DecisionSource source, string? rule, string reason, string trailEntry) =>
        this with
        {
            Verdict = Verdict.Deny,
            Reason = reason,
            RuleName = rule,
            Source = source,
            Trail = Trail is null ? null : [.. Trail, trailEntry],
        };

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
        (DecisionSource.Approval, { } rule) =>
            $"Blocked by guardrails approval for rule '{rule}': {Reason}",
        (DecisionSource.Scanner, { } scanner) => $"Blocked by guardrails scanner '{scanner}': {Reason}",
        (_, { } rule) => $"Blocked by guardrails policy rule '{rule}': {Reason}",
        _ => $"Blocked by guardrails policy: {Reason}",
    };
}
