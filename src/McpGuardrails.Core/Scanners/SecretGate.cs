using System.Text.Json;
using McpGuardrails.Core.Policy;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Scanners;

/// <summary>
/// What the gate did to a tool result.
/// </summary>
public enum RedactionEffect
{
    /// <summary>Nothing matched, or result scanning is off. The result is untouched.</summary>
    None,

    /// <summary>Secrets were replaced with markers and the result forwarded.</summary>
    Redacted,

    /// <summary>The result was withheld and replaced with a tool error.</summary>
    Blocked,
}

/// <summary>
/// The outcome of redacting one tool result.
/// </summary>
/// <param name="Result">What to send to the client - the original, or a replacement.</param>
/// <param name="Report">What the scanner found.</param>
/// <param name="Effect">What was done about it.</param>
public sealed record RedactionOutcome(CallToolResult Result, SecretReport Report, RedactionEffect Effect)
{
    /// <summary>The effect as a log-friendly string, or null when nothing happened.</summary>
    public string? Describe() => Effect switch
    {
        RedactionEffect.Redacted => "redacted",
        RedactionEffect.Blocked => "blocked",
        _ => null,
    };
}

/// <summary>
/// The arguments of one call, as the model sent them and as they may be logged.
/// </summary>
/// <param name="Arguments">What the model sent.</param>
/// <param name="Redacted">
/// What the audit log may record: the same values with secrets replaced, or the
/// originals when nothing matched or argument scanning is off.
/// </param>
/// <param name="Report">What the scanner found.</param>
public sealed record ArgumentScan(
    IReadOnlyDictionary<string, JsonElement>? Arguments,
    IReadOnlyDictionary<string, JsonElement>? Redacted,
    SecretReport Report);

/// <summary>
/// Applies the secret scanner to both halves of a call: the arguments going out
/// and the result coming back.
/// </summary>
/// <remarks>
/// Four touch points, because there are four places a secret can end up, and the
/// pipeline reaches them at different moments:
///
/// <list type="bullet">
/// <item><see cref="ScanArguments"/> - the audit log, for every call including
/// the ones the policy refuses. The audit filter is outermost, and a refused call
/// never reaches the filters inside it.</item>
/// <item><see cref="Apply"/> - the decision, for <c>arguments: block</c>. A
/// refusal belongs with the other refusals, before approval and budget, so a
/// human is never asked about a call that is going to be refused anyway and a
/// call that never left is never charged.</item>
/// <item><see cref="RedactForwarded"/> - the server, for <c>arguments:
/// redact</c>, after every gate has said yes.</item>
/// <item><see cref="Inspect"/> - the model, on the way back.</item>
/// </list>
///
/// The arguments may therefore be scanned twice in one call. That is the
/// existing trade in this pipeline - the audit filter resolves the tool name
/// itself rather than share state with the router - and a pure function over a
/// few hundred bytes of arguments is cheaper than the coupling that would avoid
/// it.
/// </remarks>
public sealed class SecretGate
{
    /// <summary>The name a refusal for secrets in arguments is recorded under.</summary>
    /// <remarks>
    /// Shaped like the budget's <c>session.max_cost</c>: the policy key that
    /// produced the refusal, so the audit log's <c>rule</c> field points an
    /// operator at the line of configuration to change.
    /// </remarks>
    public const string ArgumentRule = "secrets.arguments";

    private readonly SecretScannerSettings _settings;

    /// <param name="settings">What to do with secrets in each direction.</param>
    public SecretGate(SecretScannerSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        _settings = settings;
    }

    /// <summary>A gate that scans nothing in either direction.</summary>
    public static SecretGate Off { get; } = new(SecretScannerSettings.Disabled);

    /// <summary>
    /// Scans a call's arguments, producing the copy that is safe to log.
    /// </summary>
    /// <param name="arguments">The arguments the client sent, if any.</param>
    public ArgumentScan ScanArguments(IDictionary<string, JsonElement>? arguments)
    {
        var original = arguments?.AsReadOnly();

        if (arguments is null || _settings.EffectiveArguments is SecretArgumentAction.Off)
        {
            return new ArgumentScan(original, original, SecretReport.Clean);
        }

        var (redacted, report) = RedactArguments(arguments);

        return new ArgumentScan(original, redacted?.AsReadOnly() ?? original, report);
    }

    /// <summary>
    /// Refuses a call whose arguments carry a secret, under <c>arguments: block</c>.
    /// </summary>
    /// <param name="decision">What the policy decided.</param>
    /// <param name="arguments">The arguments the client sent, if any.</param>
    /// <returns>The original decision, or a denial naming what was found.</returns>
    public Decision Apply(Decision decision, IDictionary<string, JsonElement>? arguments)
    {
        ArgumentNullException.ThrowIfNull(decision);

        // Deny, not IsBlocked. A require_approval call is blocked only until a
        // human says yes, and a human who approves "write the deploy notes" has
        // not seen that the notes contain the production key. Refusing here,
        // before the question is asked, is the only point where that cannot slip
        // through.
        if (decision.Verdict is Verdict.Deny ||
            arguments is null ||
            _settings.EffectiveArguments is not SecretArgumentAction.Block)
        {
            return decision;
        }

        var (_, report) = RedactArguments(arguments);

        if (report.IsClean)
        {
            return decision;
        }

        return decision.RefusedBy(
            DecisionSource.Scanner,
            ArgumentRule,
            $"the arguments contain {Count(report)} ({report.Summary}), and this policy does " +
            "not let credentials or personal data leave through tool arguments. Do not retry " +
            "with the value split, encoded or paraphrased; tell the user the call needs a " +
            "secret and let them decide how to proceed.",
            $"scanner 'secrets': arguments contain {report.Summary} -> deny");
    }

    /// <summary>
    /// The arguments to forward instead, under <c>arguments: redact</c>.
    /// </summary>
    /// <param name="arguments">The arguments the client sent, if any.</param>
    /// <returns>
    /// A redacted copy, or null when the call should be forwarded as sent -
    /// because nothing matched or because the setting forwards secrets.
    /// </returns>
    public IDictionary<string, JsonElement>? RedactForwarded(IDictionary<string, JsonElement>? arguments)
    {
        if (arguments is null || _settings.EffectiveArguments is not SecretArgumentAction.Redact)
        {
            return null;
        }

        return RedactArguments(arguments).Redacted;
    }

    /// <summary>
    /// What happened to the secrets in a call's arguments, for the audit log.
    /// </summary>
    /// <param name="scan">The audit filter's own scan of the arguments.</param>
    /// <param name="decision">The final decision, if the call reached one.</param>
    /// <returns>
    /// <c>blocked</c>, <c>redacted</c>, <c>forwarded</c>, or null when nothing
    /// was found or the call was refused for some other reason.
    /// </returns>
    /// <remarks>
    /// <c>forwarded</c> is the word an auditor most needs to be able to search
    /// for: the secret is out of the log, but it did reach the server.
    /// </remarks>
    public string? DescribeArguments(ArgumentScan scan, Decision? decision)
    {
        ArgumentNullException.ThrowIfNull(scan);

        if (scan.Report.IsClean)
        {
            return null;
        }

        if (decision is { Source: DecisionSource.Scanner, RuleName: ArgumentRule })
        {
            return "blocked";
        }

        // Refused by policy, approval or budget: nothing left, so there is no
        // fate of the secret to report beyond the names already logged.
        if (decision?.IsBlocked is true)
        {
            return null;
        }

        return _settings.EffectiveArguments is SecretArgumentAction.Redact ? "redacted" : "forwarded";
    }

    /// <summary>
    /// Redacts or withholds a result, as configured.
    /// </summary>
    /// <param name="result">What the downstream server returned.</param>
    /// <param name="toolName">Client-visible tool name, named in the notice.</param>
    public RedactionOutcome Inspect(CallToolResult result, string toolName)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentException.ThrowIfNullOrWhiteSpace(toolName);

        if (_settings.EffectiveResults is SecretResultAction.Off)
        {
            return new RedactionOutcome(result, SecretReport.Clean, RedactionEffect.None);
        }

        var report = SecretReport.Clean;
        var content = new List<ContentBlock>(result.Content.Count + 1);

        foreach (var block in result.Content)
        {
            var (redacted, found) = RedactBlock(block);
            content.Add(redacted);
            report = report.Merge(found);
        }

        // Kept as the original property rather than ResultContent.StructuredOf,
        // so a default (Undefined) payload is forwarded exactly as it arrived.
        var structured = result.StructuredContent;

        if (ResultContent.StructuredOf(result) is { } payload)
        {
            var redaction = SecretScanner.RedactJson(payload, null, _settings.IncludePii);
            structured = redaction.Element;
            report = report.Merge(redaction.Report);
        }

        if (report.IsClean)
        {
            return new RedactionOutcome(result, report, RedactionEffect.None);
        }

        if (_settings.EffectiveResults is SecretResultAction.Block)
        {
            return new RedactionOutcome(Block(result, report, toolName), report, RedactionEffect.Blocked);
        }

        content.Add(new TextContentBlock { Text = Notice(report, toolName) });

        // _meta is protocol bookkeeping addressed to the client, not content, so
        // the rebuilt result carries it through as is.
        var replacement = new CallToolResult
        {
            IsError = result.IsError,
            Meta = result.Meta,
            StructuredContent = structured,
            Content = content,
        };

        return new RedactionOutcome(replacement, report, RedactionEffect.Redacted);
    }

    private (Dictionary<string, JsonElement>? Redacted, SecretReport Report) RedactArguments(
        IDictionary<string, JsonElement> arguments)
    {
        var report = SecretReport.Clean;
        var redacted = new Dictionary<string, JsonElement>(arguments.Count, StringComparer.Ordinal);

        foreach (var (name, value) in arguments)
        {
            var redaction = SecretScanner.RedactJson(value, name, _settings.IncludePii);
            redacted[name] = redaction.Element;
            report = report.Merge(redaction.Report);
        }

        return (report.IsClean ? null : redacted, report);
    }

    /// <remarks>
    /// The same shapes the injection gate reads, for the same reason: they are
    /// where model-readable text arrives.
    /// </remarks>
    private (ContentBlock Block, SecretReport Report) RedactBlock(ContentBlock block)
    {
        if (ResultContent.TextOf(block) is not { } text)
        {
            return (block, SecretReport.Clean);
        }

        var redaction = SecretScanner.Redact(text, _settings.IncludePii);

        return redaction.Report.IsClean
            ? (block, redaction.Report)
            : (ResultContent.WithText(block, redaction.Text), redaction.Report);
    }

    /// <remarks>
    /// Appended after the content rather than before it, and the warning that
    /// matters is the second sentence. The failure this guards against is not
    /// the model seeing a marker; it is the model reading a config file, editing
    /// one line, and writing the whole file back - markers included - over the
    /// real keys.
    /// </remarks>
    private static string Notice(SecretReport report, string toolName) =>
        $"[guardrails] {Count(report)} {(report.Count == 1 ? "was" : "were")} redacted from " +
        $"the output of '{toolName}' ({report.Summary}) and replaced with [REDACTED:<kind>] " +
        "markers. The markers are placeholders, not the real values: do not write them back " +
        "into a file, pass them to another tool, or treat them as the actual data. If the " +
        "task needs a real value, tell the user it was withheld and let them supply it.";

    /// <remarks>
    /// A tool error worded like the injection gate's, and for the same reason it
    /// says the content was withheld rather than that the tool failed: an agent
    /// that believes a tool is broken goes looking for another way to read the
    /// same file.
    /// </remarks>
    private static CallToolResult Block(CallToolResult result, SecretReport report, string toolName) =>
        ResultContent.Blocked(
            result,
            "secrets",
            toolName,
            $"contained {Count(report)} ({report.Summary})",
            "Do not try to read the same content another way; tell the user the tool returned " +
            "credentials or personal data that this proxy is configured not to pass on.");

    private static string Count(SecretReport report) =>
        ResultContent.CountOf(report.Count, "sensitive value", "sensitive values");
}
