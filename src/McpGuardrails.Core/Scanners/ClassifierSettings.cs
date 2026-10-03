using System.Globalization;
using System.Text.Json.Serialization;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Scanners;

/// <summary>
/// When the second-stage classifier is consulted.
/// </summary>
/// <remarks>
/// Serialized as a string, like <see cref="ScanAction"/>, so the policy file
/// reads as prose.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<ClassifierMode>))]
public enum ClassifierMode
{
    /// <summary>Never call the classifier.</summary>
    [JsonStringEnumMemberName("off")]
    Off,

    /// <summary>
    /// Call it only for results the heuristics flagged, to confirm or discount
    /// the finding.
    /// </summary>
    /// <remarks>
    /// The default once a <c>classifier:</c> block exists. It costs nothing on a
    /// clean result - which is nearly every result - so turning it on does not
    /// put a network round trip in front of every tool call.
    /// </remarks>
    [JsonStringEnumMemberName("confirm")]
    Confirm,

    /// <summary>
    /// Call it for every result, so it can also catch what the heuristics miss.
    /// </summary>
    /// <remarks>
    /// The only mode that can find an injection the heuristics did not, and the
    /// expensive one: every forwarded call pays a model round trip in latency and
    /// in tokens.
    /// </remarks>
    [JsonStringEnumMemberName("all")]
    All,
}

/// <summary>
/// The <c>scanners.injection.classifier:</c> block: an optional LLM that reads a
/// tool result and judges whether it is an injection attempt.
/// </summary>
/// <remarks>
/// Off unless asked for. The heuristics are free, local and deterministic; this
/// sends tool output to a third party, costs money per call and adds latency, and
/// none of those is a default anybody should discover after the fact.
///
/// The block being present is the request: <c>classifier: {}</c> means
/// <see cref="ClassifierMode.Confirm"/> with every default. A block that set a
/// model and a timeout but quietly did nothing because <c>mode:</c> was missing
/// would be the kind of configured-but-inert guardrail the rest of the policy
/// format refuses to accept.
/// </remarks>
public sealed record ClassifierSettings
{
    /// <summary>The model asked when the policy does not name one.</summary>
    /// <remarks>
    /// The smallest, fastest current model. This is a one-word classification of
    /// a bounded input, on the hot path of a tool call; a larger model buys
    /// little accuracy here and costs latency on every flagged result.
    /// </remarks>
    public const string DefaultModel = "claude-haiku-4-5-20251001";

    /// <summary>The environment variable the API key is read from by default.</summary>
    public const string DefaultApiKeyEnv = "ANTHROPIC_API_KEY";

    /// <summary>Where the Messages API lives by default.</summary>
    public const string DefaultBaseUrl = "https://api.anthropic.com";

    /// <summary>How long a verdict may take before the heuristic verdict stands.</summary>
    /// <remarks>
    /// Five seconds. A classifier is a second opinion, and a tool call that
    /// stalls waiting for a second opinion is a worse failure than going with the
    /// first one.
    /// </remarks>
    public const int DefaultTimeoutMs = 5_000;

    /// <summary>Upper bound on <c>timeout_ms</c>.</summary>
    public const int MaxTimeoutMs = 60_000;

    /// <summary>How much result text the classifier is shown, in characters.</summary>
    /// <remarks>
    /// Roughly 8k tokens: enough for any prose a model is likely to act on, small
    /// enough that a multi-megabyte result does not become a multi-dollar call.
    /// </remarks>
    public const int DefaultMaxChars = 32_000;

    /// <summary>Upper bound on <c>max_chars</c>.</summary>
    public const int MaxMaxChars = 400_000;

    /// <summary>A classifier block with every default, which is <c>confirm</c>.</summary>
    public static ClassifierSettings Default { get; } = new();

    /// <summary>When to consult the classifier: <c>off</c>, <c>confirm</c> or <c>all</c>.</summary>
    [JsonPropertyName("mode")]
    public ClassifierMode? Mode { get; init; }

    /// <inheritdoc cref="Mode" />
    [JsonIgnore]
    public ClassifierMode EffectiveMode => Mode ?? ClassifierMode.Confirm;

    /// <summary>True when the classifier should not be called.</summary>
    [JsonIgnore]
    public bool IsOff => EffectiveMode is ClassifierMode.Off;

    /// <summary>The model to ask.</summary>
    [JsonPropertyName("model")]
    public string? Model { get; init; }

    /// <inheritdoc cref="Model" />
    [JsonIgnore]
    public string EffectiveModel => Model ?? DefaultModel;

    /// <summary>The NAME of the environment variable holding the API key.</summary>
    /// <remarks>
    /// A name rather than the key, so the policy file can be committed and
    /// shared. A secret in a YAML file is a secret in a repository.
    /// </remarks>
    [JsonPropertyName("api_key_env")]
    public string? ApiKeyEnv { get; init; }

    /// <inheritdoc cref="ApiKeyEnv" />
    [JsonIgnore]
    public string EffectiveApiKeyEnv => ApiKeyEnv ?? DefaultApiKeyEnv;

    /// <summary>Base URL of the Messages API, for a gateway or a test double.</summary>
    [JsonPropertyName("base_url")]
    public string? BaseUrl { get; init; }

    /// <inheritdoc cref="BaseUrl" />
    [JsonIgnore]
    public Uri EffectiveBaseUrl => new(BaseUrl ?? DefaultBaseUrl, UriKind.Absolute);

    /// <summary>How long to wait for a verdict, in milliseconds.</summary>
    [JsonPropertyName("timeout_ms")]
    public int? TimeoutMs { get; init; }

    /// <inheritdoc cref="TimeoutMs" />
    [JsonIgnore]
    public TimeSpan EffectiveTimeout => TimeSpan.FromMilliseconds(TimeoutMs ?? DefaultTimeoutMs);

    /// <summary>How many characters of result text the classifier sees.</summary>
    [JsonPropertyName("max_chars")]
    public int? MaxChars { get; init; }

    /// <inheritdoc cref="MaxChars" />
    [JsonIgnore]
    public int EffectiveMaxChars => MaxChars ?? DefaultMaxChars;

    internal void Validate()
    {
        const string Key = "'scanners.injection.classifier";

        if (!Enum.IsDefined(EffectiveMode))
        {
            throw new PolicyException($"{Key}.mode' is not a known mode. Use off, confirm or all.");
        }

        if (Model is not null && string.IsNullOrWhiteSpace(Model))
        {
            throw new PolicyException($"{Key}.model' is blank. Name a model, or omit it for {DefaultModel}.");
        }

        if (ApiKeyEnv is not null && string.IsNullOrWhiteSpace(ApiKeyEnv))
        {
            throw new PolicyException(
                $"{Key}.api_key_env' is blank. Name the environment variable holding the key, " +
                $"or omit it for {DefaultApiKeyEnv}.");
        }

        ValidateBaseUrl();

        if (TimeoutMs is <= 0 or > MaxTimeoutMs)
        {
            throw new PolicyException(
                $"{Key}.timeout_ms' is {TimeoutMs}. Use 1 to {Format(MaxTimeoutMs)}, or omit it for " +
                $"{Format(DefaultTimeoutMs)}.");
        }

        if (MaxChars is <= 0 or > MaxMaxChars)
        {
            throw new PolicyException(
                $"{Key}.max_chars' is {MaxChars}. Use 1 to {Format(MaxMaxChars)}, or omit it for " +
                $"{Format(DefaultMaxChars)}.");
        }
    }

    /// <remarks>
    /// Plain http to a loopback address - a local gateway or a test double - needs
    /// no opt-in here, unlike the approval webhook: configurations (and the smoke
    /// test's fake Messages API) already rely on it, and the key never leaves the
    /// machine. Anywhere else it would cross the network in the clear.
    /// </remarks>
    private void ValidateBaseUrl()
    {
        if (BaseUrl is null)
        {
            return;
        }

        OutboundUrl.Validate(
            BaseUrl,
            "scanners.injection.classifier.base_url",
            reason: "The API key is sent with every request",
            credentialHint: "the API key is read from the variable named in 'api_key_env'",
            allowLoopbackHttp: true);
    }

    private static string Format(int value) => value.ToString(CultureInfo.InvariantCulture);
}
