using System.Text.Json.Serialization;
using McpGuardrails.Core.Access;
using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Budget;
using McpGuardrails.Core.Scanners;

namespace McpGuardrails.Core.Policy;

/// <summary>
/// A parsed policy file.
/// </summary>
/// <remarks>
/// Rules are evaluated in order and the first match wins. That is a deliberate
/// choice over "most specific wins": first-match-wins is predictable by reading
/// top to bottom, whereas specificity scoring makes people guess. Firewall rules
/// and routing tables work the same way for the same reason.
/// </remarks>
public sealed record PolicyDocument
{
    /// <summary>Rules in evaluation order, or null when the file has none.</summary>
    /// <remarks>
    /// Nullable, like every other property bound from the file, and for the same
    /// reason: <c>= []</c> here would be a lie. Property initializers are NOT
    /// applied by System.Text.Json's source-generated deserializer, so a policy
    /// file that omits <c>rules:</c> - a file that only sets <c>budgets:</c>, say
    /// - produced null and threw on the first iteration. Read it through
    /// <see cref="EffectiveRules"/>.
    /// </remarks>
    [JsonPropertyName("rules")]
    public IReadOnlyList<PolicyRule>? Rules { get; init; }

    /// <summary>The rules, or an empty list when the file declares none.</summary>
    /// <remarks>No rules means no opinion, which the evaluator turns into allow.</remarks>
    [JsonIgnore]
    public IReadOnlyList<PolicyRule> EffectiveRules => Rules ?? [];

    /// <summary>
    /// Caps on how much the agent may do, or null when nothing is capped.
    /// </summary>
    /// <remarks>
    /// Nullable for the same reason as the rule properties below: property
    /// initializers are not applied by the source-generated deserializer, so
    /// "absent" has to be modelled rather than defaulted. Read it through
    /// <see cref="EffectiveBudgets"/>.
    /// </remarks>
    [JsonPropertyName("budgets")]
    public BudgetPolicy? Budgets { get; init; }

    /// <summary>The budget section, or an empty one when the file omits it.</summary>
    [JsonIgnore]
    public BudgetPolicy EffectiveBudgets => Budgets ?? BudgetPolicy.None;

    /// <summary>
    /// Where out-of-band approval questions go, or null when none is configured.
    /// </summary>
    /// <remarks>Nullable for the same reason as <see cref="Budgets"/>.</remarks>
    [JsonPropertyName("approvers")]
    public ApproversPolicy? Approvers { get; init; }

    /// <summary>The approvers section, or an empty one when the file omits it.</summary>
    [JsonIgnore]
    public ApproversPolicy EffectiveApprovers => Approvers ?? ApproversPolicy.None;

    /// <summary>
    /// What to do with suspicious tool results, or null when the file says nothing.
    /// </summary>
    /// <remarks>
    /// Note the asymmetry with <see cref="Budgets"/>: an omitted budget section
    /// means no cap, but an omitted scanner section means the default scanner,
    /// which is ON. A cap nobody configured would be a number invented on the
    /// operator's behalf; a scanner nobody configured only adds a warning to
    /// content that already looks like an attack. Read it through
    /// <see cref="EffectiveScanners"/>.
    /// </remarks>
    [JsonPropertyName("scanners")]
    public ScannerPolicy? Scanners { get; init; }

    /// <summary>The scanner section, or the defaults when the file omits it.</summary>
    [JsonIgnore]
    public ScannerPolicy EffectiveScanners => Scanners ?? ScannerPolicy.Default;

    /// <summary>
    /// Who may reach the proxy over HTTP, or null for the static bearer token.
    /// </summary>
    /// <remarks>Nullable for the same reason as <see cref="Budgets"/>.</remarks>
    [JsonPropertyName("access")]
    public AccessPolicy? Access { get; init; }

    /// <summary>The access section, or an empty one when the file omits it.</summary>
    [JsonIgnore]
    public AccessPolicy EffectiveAccess => Access ?? AccessPolicy.None;

    /// <summary>An empty policy: everything allowed, nothing configured.</summary>
    public static PolicyDocument Empty { get; } = new();

    /// <summary>
    /// Rules whose <c>server:</c> pattern matches none of
    /// <paramref name="serverNames"/>, by name.
    /// </summary>
    /// <remarks>
    /// For <c>validate</c>: a rule scoped to a server that is not configured -
    /// renamed by <c>import</c>, say, or simply misspelt - never matches, and a
    /// guardrail that never matches is a guardrail that is not there.
    /// </remarks>
    public IReadOnlyList<string> RulesMatchingNoServer(IReadOnlyCollection<string> serverNames)
    {
        ArgumentNullException.ThrowIfNull(serverNames);

        return
        [
            .. EffectiveRules
                .Where(rule => rule.EffectiveMatch.Server is { } pattern &&
                               !serverNames.Any(name => GlobMatcher.IsMatch(pattern, name)))
                .Select(rule => rule.Name),
        ];
    }
}

/// <summary>
/// One rule: what to match, and what to do about it.
/// </summary>
public sealed record PolicyRule
{
    /// <summary>Human-readable name, used in denial messages and the trail.</summary>
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    /// <summary>
    /// Conditions that must all hold for this rule to apply, or null when the
    /// rule specifies none (a catch-all).
    /// </summary>
    /// <remarks>
    /// Nullable rather than defaulted with a property initializer. Initializers
    /// are NOT applied by System.Text.Json's source-generated deserializer, so a
    /// policy file omitting `match` produced a null here and crashed validation.
    /// Modelling "absent" explicitly is both honest and robust; read it through
    /// <see cref="EffectiveMatch"/>.
    /// </remarks>
    [JsonPropertyName("match")]
    public PolicyMatch? Match { get; init; }

    /// <summary>The rule's conditions, or a match-everything default.</summary>
    [JsonIgnore]
    public PolicyMatch EffectiveMatch => Match ?? PolicyMatch.Any;

    /// <summary>
    /// What to do when the rule applies, or null when the file does not say.
    /// </summary>
    /// <remarks>
    /// Nullable for the same reason as <see cref="Match"/>, and here the bug was
    /// worse: an omitted decision silently became Verdict.Allow, because Allow is
    /// the zero value of the enum. A rule written to block something would have
    /// permitted it instead. Read it through <see cref="EffectiveDecision"/>,
    /// which fails closed.
    /// </remarks>
    [JsonPropertyName("decision")]
    public Verdict? Decision { get; init; }

    /// <summary>The decision, defaulting to Deny when unspecified.</summary>
    /// <remarks>Absent means deny: a security policy must fail closed.</remarks>
    [JsonIgnore]
    public Verdict EffectiveDecision => Decision ?? Verdict.Deny;

    /// <summary>What a call matching this rule costs against the budget.</summary>
    /// <remarks>
    /// The weight in <c>budgets.*.max_cost</c>. Omitted means
    /// <see cref="DefaultCost"/>, so every call counts for something without any
    /// rule having to say so; <c>cost: 0</c> makes a class of calls free, which is
    /// the natural way to let reads run unbounded while writes are capped.
    ///
    /// It lives on the rule rather than in a separate cost table because a rule
    /// already expresses "these calls" precisely - tool glob, annotations,
    /// arguments. A second matcher would be a second thing to learn, and a second
    /// place for the two to disagree about which call is which.
    /// </remarks>
    [JsonPropertyName("cost")]
    public long? Cost { get; init; }

    /// <summary>What a call costs when no rule sets a price: one.</summary>
    public const long DefaultCost = 1;

    /// <summary>The rule's cost, defaulting to <see cref="DefaultCost"/>.</summary>
    [JsonIgnore]
    public long EffectiveCost => Cost ?? DefaultCost;

    /// <summary>How to ask for approval, on a <c>require_approval</c> rule.</summary>
    /// <remarks>
    /// Optional: a bare <c>decision: require_approval</c> asks the client and
    /// waits five minutes, which is the sensible default for the common case.
    /// </remarks>
    [JsonPropertyName("approval")]
    public ApprovalSettings? Approval { get; init; }

    /// <summary>
    /// Explanation handed to the model when this rule blocks a call.
    /// </summary>
    /// <remarks>
    /// Optional, but omitting it wastes the rule's best feature. Write it as an
    /// instruction to the agent, not a note to yourself.
    /// </remarks>
    [JsonPropertyName("message")]
    public string? Message { get; init; }

    /// <summary>Validates the rule, throwing with a message naming the problem.</summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Name))
        {
            throw new PolicyException("Every rule needs a non-empty 'name'.");
        }

        if (!Enum.IsDefined(EffectiveDecision))
        {
            throw new PolicyException(
                $"Rule '{Name}' has an unknown decision. " +
                "Use allow, deny or require_approval.");
        }

        // Zero is legal (a free call); negative would refund budget, which turns
        // a cap into something an agent can top up by calling the cheap tool.
        if (EffectiveCost < 0)
        {
            throw new PolicyException(
                $"Rule '{Name}' has a negative 'cost' ({EffectiveCost}). " +
                "Use 0 to make matching calls free.");
        }

        // An approval block on an allow or deny rule looks like a gate and is
        // not one. Refusing it costs an operator one startup error; accepting it
        // costs them a destructive call they believed was being reviewed.
        if (Approval is not null && EffectiveDecision is not Verdict.RequireApproval)
        {
            throw new PolicyException(
                $"Rule '{Name}' has an 'approval' block but its decision is " +
                $"'{EffectiveDecision.ToWireName()}', so nobody would ever be " +
                "asked. Use 'decision: require_approval', or remove the block.");
        }

        Approval?.Validate(Name);

        EffectiveMatch.Validate(Name);
    }
}

/// <summary>
/// The conditions of a rule. All specified conditions must hold (logical AND).
/// </summary>
/// <remarks>
/// Five kinds of condition, deliberately ordered cheapest-first in
/// <see cref="RuleMatcher"/>: a tool-name glob, a server-name glob, the caller's
/// identity, the tool's advertised behaviour hints, and predicates over the
/// arguments the model supplied. Most rules never get past the name.
/// </remarks>
public sealed record PolicyMatch
{
    /// <summary>A match with no conditions, which applies to every tool.</summary>
    public static PolicyMatch Any { get; } = new();

    /// <summary>
    /// Tool name to match, as the client sees it (e.g. <c>fs__write_file</c>).
    /// </summary>
    /// <remarks>
    /// A glob: <c>*</c> matches any run of characters and <c>?</c> exactly one,
    /// so <c>fs__*</c> covers a whole server and <c>"*__delete_*"</c> covers a
    /// verb across every server. A pattern with no wildcard is an exact, ordinal,
    /// case-sensitive match, so existing policy files keep their meaning.
    ///
    /// Quote any pattern that starts with <c>*</c> in the policy file: a bare
    /// leading <c>*</c> is YAML's alias indicator, so <c>tool: *__delete_*</c> is
    /// a syntax error rather than a glob.
    /// </remarks>
    [JsonPropertyName("tool")]
    public string? Tool { get; init; }

    /// <summary>
    /// Name of the downstream server that owns the tool, as named in the servers
    /// file (e.g. <c>github</c>).
    /// </summary>
    /// <remarks>
    /// A glob, like <see cref="Tool"/>. It says the same thing as a
    /// <c>tool: github__*</c> pattern, but reads as what it means, and it keeps
    /// meaning it when a rule also narrows by annotations or arguments.
    ///
    /// A call to a tool no server advertises has no server, so a <c>server:</c>
    /// condition never matches it - the same way a predicate on a missing
    /// argument does not. The catch-all at the bottom of the file decides those.
    /// </remarks>
    [JsonPropertyName("server")]
    public string? Server { get; init; }

    /// <summary>
    /// The caller's identity, from the access token's principal claim.
    /// </summary>
    /// <remarks>
    /// A glob, like <see cref="Tool"/>. Only HTTP calls authenticated through
    /// <c>access.oauth</c> have a principal; for any other call the condition
    /// never matches, the same way <see cref="Server"/> never matches an unknown
    /// tool. A policy using it without <c>access.oauth</c> is refused at load,
    /// because a deny rule that can never match is a guardrail that is not there.
    /// </remarks>
    [JsonPropertyName("principal")]
    public string? Principal { get; init; }

    /// <summary>
    /// Groups, from the access token's groups claim; the caller must be in at
    /// least one.
    /// </summary>
    /// <remarks>Exact, case-sensitive names. Requires <c>access.oauth</c>, like <see cref="Principal"/>.</remarks>
    [JsonPropertyName("groups")]
    public IReadOnlyList<string>? Groups { get; init; }

    /// <summary>True when the match keys on who is calling.</summary>
    [JsonIgnore]
    public bool UsesIdentity => Principal is not null || Groups is not null;

    /// <summary>Behaviour hints the tool must advertise, if any.</summary>
    [JsonPropertyName("annotations")]
    public AnnotationMatch? Annotations { get; init; }

    /// <summary>
    /// Conditions on the call's arguments; all must hold.
    /// </summary>
    /// <remarks>
    /// Named <c>args</c> in the policy file because that is what the thing is
    /// called at the call site, and policy files are read far more often than
    /// this class is.
    /// </remarks>
    [JsonPropertyName("args")]
    public IReadOnlyList<ArgumentPredicate>? Arguments { get; init; }

    /// <summary>True when this match specifies no conditions at all.</summary>
    /// <remarks>
    /// A rule that matches everything is legal and useful (a catch-all deny at
    /// the bottom of the file), but it is worth being able to detect.
    /// </remarks>
    [JsonIgnore]
    public bool IsCatchAll =>
        Tool is null && Server is null && !UsesIdentity && Annotations is null && Arguments is null;

    internal void Validate(string ruleName)
    {
        if (Tool is not null && string.IsNullOrWhiteSpace(Tool))
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has an empty 'tool'. " +
                "Omit the field entirely to match every tool.");
        }

        if (Server is not null && string.IsNullOrWhiteSpace(Server))
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has an empty 'server'. " +
                "Omit the field entirely to match tools from every server.");
        }

        if (Principal is not null && string.IsNullOrWhiteSpace(Principal))
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has an empty 'principal'. " +
                "Omit the field entirely to match every caller.");
        }

        if (Groups is not null && (Groups.Count == 0 || Groups.Any(string.IsNullOrWhiteSpace)))
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has an empty 'groups' list or an empty group name. " +
                "Omit the field entirely to match regardless of groups.");
        }

        Annotations?.Validate(ruleName);

        if (Arguments is null)
        {
            return;
        }

        if (Arguments.Count == 0)
        {
            throw new PolicyException(
                $"Rule '{ruleName}' has an empty 'args' list. " +
                "Omit the field entirely to match regardless of arguments.");
        }

        foreach (var predicate in Arguments)
        {
            predicate.Validate(ruleName);
        }
    }
}

/// <summary>
/// Raised for a malformed policy file.
/// </summary>
/// <remarks>
/// A dedicated exception type so the CLI can print a clean configuration error
/// instead of a stack trace. A bad policy is a user mistake, not a crash.
/// </remarks>
public sealed class PolicyException : Exception
{
    public PolicyException(string message) : base(message)
    {
    }

    public PolicyException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
