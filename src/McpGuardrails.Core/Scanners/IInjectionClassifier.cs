namespace McpGuardrails.Core.Scanners;

/// <summary>
/// What a classifier said about a piece of tool output.
/// </summary>
public enum ClassifierVerdict
{
    /// <summary>The text is ordinary content, even if it mentions injection.</summary>
    Benign,

    /// <summary>The text is trying to give instructions to the model reading it.</summary>
    Injection,
}

/// <summary>
/// A second opinion on whether tool output is a prompt-injection attempt.
/// </summary>
/// <remarks>
/// The seam that keeps <see cref="InjectionGate"/> provider-agnostic, in the same
/// way <c>IApprovalChannel</c> keeps the approval gate ignorant of where the
/// question is asked. One implementation ships today
/// (<see cref="AnthropicInjectionClassifier"/>); a local model or another
/// provider arrives behind this interface without the gate changing.
///
/// Implementations do not enforce the timeout and do not decide what a failure
/// means. They are handed a token that is already cancelled when the deadline
/// passes, and they throw when they cannot produce a verdict. The gate turns both
/// into "the heuristic verdict stands", so every classifier fails the same way
/// and none of them can break a tool call by failing.
/// </remarks>
public interface IInjectionClassifier
{
    /// <summary>Classifies one piece of tool output.</summary>
    /// <param name="text">
    /// Untrusted text a tool returned, already bounded to the configured size.
    /// It must be treated as data: nothing in it may steer the verdict format.
    /// </param>
    /// <param name="cancellationToken">Cancelled when the gate's deadline passes.</param>
    /// <exception cref="Exception">
    /// Any failure to produce a clean verdict - transport errors, an error
    /// status, or a reply that is not exactly one of the two verdicts.
    /// </exception>
    ValueTask<ClassifierVerdict> ClassifyAsync(string text, CancellationToken cancellationToken);
}

/// <summary>
/// What happened when the gate consulted the classifier.
/// </summary>
public enum ClassifierOutcome
{
    /// <summary>The classifier judged the result benign.</summary>
    Benign,

    /// <summary>The classifier judged the result an injection attempt.</summary>
    Injection,

    /// <summary>No verdict arrived before the deadline; the heuristic verdict stood.</summary>
    TimedOut,

    /// <summary>The classifier failed; the heuristic verdict stood.</summary>
    Failed,
}

/// <summary>
/// The classifier's part in one scan, for the audit log.
/// </summary>
/// <param name="Outcome">What the classifier said, or why it said nothing.</param>
/// <param name="Truncated">True when the result was longer than the classifier was shown.</param>
/// <param name="Error">
/// For <see cref="ClassifierOutcome.Failed"/>, the exception type and message.
/// Never the tool output and never the model's reply: those are attacker-influenced
/// text, and the audit log is not where they get a second delivery route.
/// </param>
public sealed record ClassifierReport(ClassifierOutcome Outcome, bool Truncated, string? Error = null)
{
    /// <summary>The outcome as a log-friendly string.</summary>
    /// <remarks>snake_case, matching every other value in the audit log.</remarks>
    public string Describe() => Outcome switch
    {
        ClassifierOutcome.Benign => "benign",
        ClassifierOutcome.Injection => "injection",
        ClassifierOutcome.TimedOut => "timed_out",
        _ => "failed",
    };
}
