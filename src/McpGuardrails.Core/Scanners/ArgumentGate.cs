using System.Text.Json;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Scanners;

/// <summary>What the argument gate did to a call.</summary>
public enum ArgumentEffect
{
    /// <summary>
    /// Nothing: no hit, scanning off, or the call was already refused by an
    /// earlier gate, so there was nothing left to act on.
    /// </summary>
    None,

    /// <summary>The hits were recorded and the call left as it was.</summary>
    Audited,

    /// <summary>The call was sent to a human, with the hits named in the question.</summary>
    Approval,

    /// <summary>The call was refused.</summary>
    Blocked,
}

/// <summary>The argument gate's verdict on one call.</summary>
/// <param name="Decision">The decision after the gate: unchanged, escalated, or refused.</param>
/// <param name="Findings">What the detectors found.</param>
/// <param name="Effect">What the gate did about it.</param>
public sealed record ArgumentOutcome(Decision Decision, ArgumentFindings Findings, ArgumentEffect Effect)
{
    /// <summary>The effect for the audit log's <c>argument_hits_action</c>, or null when there was none.</summary>
    public string? Describe() => Effect switch
    {
        ArgumentEffect.Audited => "audited",
        ArgumentEffect.Approval => "approval",
        ArgumentEffect.Blocked => "blocked",
        _ => null,
    };
}

/// <summary>
/// Applies the argument detectors to a call's decision: record, ask a human, or refuse.
/// </summary>
/// <remarks>
/// Runs after the policy and the secret scanner and before approval, and both
/// halves of that matter. Before approval, so <c>approve</c> can turn an allowed
/// call into a question and so a call this gate blocks never reaches a human.
/// After the policy, so a call the policy already refused is not refused twice -
/// but not suppressed by it either: an explicit <c>allow</c> still goes through
/// the detectors, and the only way to exempt a tool is an override, which says
/// so in the <c>scanners:</c> section where a reviewer looks for it.
/// </remarks>
public sealed class ArgumentGate
{
    /// <summary>Prefix of the rule name a refusal or escalation is recorded under.</summary>
    /// <remarks>
    /// Followed by the detector, e.g. <c>arguments.ssrf</c>: the policy key that
    /// produced the outcome, like the secret scanner's <c>secrets.arguments</c>,
    /// so the audit log's <c>rule</c> field points an operator at what to change.
    /// </remarks>
    public const string RulePrefix = "arguments.";

    private readonly ArgumentScannerSettings _settings;

    /// <param name="settings">Which detectors run on which tools, and what a hit does.</param>
    /// <exception cref="PolicyException">
    /// The settings name an unknown detector or action - possible when they were
    /// built in code rather than loaded, which validates them too. Refused here
    /// rather than read as "no detector", which would be a silent fail-open.
    /// </exception>
    public ArgumentGate(ArgumentScannerSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        settings.Validate();
        _settings = settings;
    }

    /// <summary>A gate that scans nothing.</summary>
    public static ArgumentGate Off { get; } = new(ArgumentScannerSettings.Disabled);

    /// <summary>Scans a call's arguments and applies the configured action to its decision.</summary>
    /// <param name="decision">The decision so far.</param>
    /// <param name="toolName">Client-visible tool name, for overrides and shell-tool detection.</param>
    /// <param name="arguments">The arguments as the model sent them, before any redaction.</param>
    public ArgumentOutcome Apply(
        Decision decision,
        string toolName,
        IEnumerable<KeyValuePair<string, JsonElement>>? arguments)
    {
        ArgumentNullException.ThrowIfNull(decision);
        ArgumentNullException.ThrowIfNull(toolName);

        var (action, detectors) = _settings.For(toolName);

        if (action is ArgumentAction.Off)
        {
            return new ArgumentOutcome(decision, ArgumentFindings.Clean, ArgumentEffect.None);
        }

        // Scanned even when the call is already refused: the audit log should
        // say what a refused call carried, and an attacker probing with denied
        // calls is exactly who an operator wants to see.
        var findings = ArgumentScanner.Scan(toolName, arguments, detectors);

        if (findings.IsClean || decision.Verdict is Verdict.Deny)
        {
            return new ArgumentOutcome(decision, findings, ArgumentEffect.None);
        }

        var rule = RulePrefix + findings.Hits[0].Detector;

        // Every message below is built from these two pieces, so the model, the
        // approver and --explain read the same words. Both are the proxy's own:
        // fixed descriptions, detector names and argument paths made only of
        // plain names (see ArgumentHit), never the model's text.
        var found = $"{string.Join("; ", findings.Hits.Select(hit => ArgumentDetector.Describe(hit.Detector)))} " +
                    $"({findings.Summary})";
        string Trail(string verdict) => $"scanner 'arguments': {findings.Summary} -> {verdict}";

        return action switch
        {
            ArgumentAction.Block => new ArgumentOutcome(
                decision.RefusedBy(
                    DecisionSource.Scanner,
                    rule,
                    $"the arguments contain {found}, and this policy refuses such calls for this tool. " +
                    "Do not retry with the value encoded, split or reworded; if the task needs it, tell " +
                    "the user what you were trying to do and let them decide.",
                    Trail("deny")),
                findings,
                ArgumentEffect.Blocked),

            ArgumentAction.Approve => new ArgumentOutcome(
                Escalate(decision, rule, found, Trail("require_approval")),
                findings,
                ArgumentEffect.Approval),

            _ => new ArgumentOutcome(
                decision with { Trail = Extend(decision.Trail, Trail("audit")) },
                findings,
                ArgumentEffect.Audited),
        };
    }

    /// <remarks>
    /// A call the policy already sends to a human keeps its rule, its approver
    /// and its timeout - the policy chose those deliberately - and only gains
    /// the note. An allowed call becomes a <c>require_approval</c> under this
    /// gate's rule name with the default approval settings: asked in-band, and
    /// refused if nobody answers.
    /// </remarks>
    private static Decision Escalate(Decision decision, string rule, string found, string trailEntry)
    {
        var note = $"Guardrails flagged its arguments: they contain {found}. Check the arguments before approving.";
        var trail = Extend(decision.Trail, trailEntry);

        return decision.Verdict is Verdict.RequireApproval
            ? decision with { ApprovalNote = note, Trail = trail }
            : decision with
            {
                Verdict = Verdict.RequireApproval,
                Reason = $"the arguments contain {found}, so a human has to approve the call.",
                RuleName = rule,
                Source = DecisionSource.Scanner,
                ApprovalNote = note,
                Trail = trail,
            };
    }

    private static IReadOnlyList<string>? Extend(IReadOnlyList<string>? trail, string entry) =>
        trail is null ? null : [.. trail, entry];
}
