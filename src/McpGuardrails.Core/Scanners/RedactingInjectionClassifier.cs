namespace McpGuardrails.Core.Scanners;

/// <summary>
/// Redacts secrets from tool output before another classifier sees it.
/// </summary>
/// <remarks>
/// The injection scanner is the innermost filter, so on the way back it runs
/// before secret redaction does. That order is deliberate - the scanner must see
/// what the server returned, and must not scan the redaction notice, whose
/// "do not pass them to another tool" wording is exactly what its heuristics
/// look for. But it means the classifier would be handed the raw result, and the
/// classifier is a network call to a third party. A credential sent there has
/// leaked whether or not the model ever sees it.
///
/// So the text is redacted here, on its way out, and nowhere else. It is
/// unconditional - even with <c>scanners.secrets.results: off</c> - because a
/// classifier never needs a real key to recognise an injection, and its endpoint
/// need not be the model provider the operator chose to trust with results.
/// </remarks>
public sealed class RedactingInjectionClassifier : IInjectionClassifier
{
    private readonly IInjectionClassifier _inner;
    private readonly bool _includePii;

    /// <param name="inner">The classifier that receives the redacted text.</param>
    /// <param name="includePii">Also redact emails and card numbers, as <c>scanners.secrets.pii</c> asks.</param>
    public RedactingInjectionClassifier(IInjectionClassifier inner, bool includePii)
    {
        ArgumentNullException.ThrowIfNull(inner);

        _inner = inner;
        _includePii = includePii;
    }

    /// <inheritdoc />
    public ValueTask<ClassifierVerdict> ClassifyAsync(string text, CancellationToken cancellationToken) =>
        _inner.ClassifyAsync(SecretScanner.Redact(text, _includePii).Text, cancellationToken);
}
