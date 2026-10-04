using System.Text.Json.Serialization;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Scanners;

/// <summary>
/// What to do with a call whose arguments match an argument detector.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<ArgumentAction>))]
public enum ArgumentAction
{
    /// <summary>Forward the call unchanged and record the hits in the audit log.</summary>
    /// <remarks>
    /// The zero value and the default, because the detectors are heuristics
    /// judging arguments they cannot fully understand: a path that climbs with
    /// <c>..</c> is often legitimate, and a URL to <c>localhost</c> is how a
    /// developer tests. Recording costs nothing and breaks nothing, and the log
    /// shows an operator what <c>approve</c> or <c>block</c> would have caught
    /// before they switch either on.
    /// </remarks>
    [JsonStringEnumMemberName("audit")]
    Audit,

    /// <summary>Hold the call for a human, naming what was found.</summary>
    [JsonStringEnumMemberName("approve")]
    Approve,

    /// <summary>Refuse the call.</summary>
    [JsonStringEnumMemberName("block")]
    Block,

    /// <summary>Do not scan arguments at all.</summary>
    [JsonStringEnumMemberName("off")]
    Off,
}

/// <summary>The argument detectors, by the names a policy file uses.</summary>
/// <remarks>
/// Flags rather than a list of strings internally, so "which detectors apply to
/// this tool" is one integer per call and the canonical order the findings are
/// reported in is fixed by the bit order rather than by how a file listed them.
/// </remarks>
[Flags]
public enum ArgumentDetectors
{
    /// <summary>No detector.</summary>
    None = 0,

    /// <summary>URLs pointing at internal, loopback or metadata addresses.</summary>
    Ssrf = 1,

    /// <summary>Paths to well-known credential files.</summary>
    SensitivePath = 2,

    /// <summary><c>..</c> path segments, plain or encoded.</summary>
    PathTraversal = 4,

    /// <summary>Shell metacharacters in command-like arguments.</summary>
    ShellMetachar = 8,

    /// <summary>Every detector.</summary>
    All = Ssrf | SensitivePath | PathTraversal | ShellMetachar,
}

/// <summary>Names and descriptions of the argument detectors.</summary>
public static class ArgumentDetector
{
    /// <summary>Requests to internal network addresses.</summary>
    public const string Ssrf = "ssrf";

    /// <summary>Reads of credential files.</summary>
    public const string SensitivePath = "sensitive-path";

    /// <summary>Path traversal.</summary>
    public const string PathTraversal = "path-traversal";

    /// <summary>Shell metacharacters in arguments that end up in a shell.</summary>
    public const string ShellMetachar = "shell-metachar";

    /// <summary>Arguments too large or too deeply nested to inspect in full.</summary>
    /// <remarks>
    /// A finding rather than a skipped check, so padding an argument past the
    /// limit is not a way to hide a URL behind it. Not configurable: it is not a
    /// detector of its own but the price of having the others.
    /// </remarks>
    public const string TooLarge = "argument-too-large";

    /// <summary>The configurable detectors, in reporting order.</summary>
    public static IReadOnlyList<string> Configurable { get; } =
        [Ssrf, SensitivePath, PathTraversal, ShellMetachar];

    /// <summary>The flag for a detector name, or <see cref="ArgumentDetectors.None"/> when unknown.</summary>
    public static ArgumentDetectors Parse(string? name) => name switch
    {
        Ssrf => ArgumentDetectors.Ssrf,
        SensitivePath => ArgumentDetectors.SensitivePath,
        PathTraversal => ArgumentDetectors.PathTraversal,
        ShellMetachar => ArgumentDetectors.ShellMetachar,
        _ => ArgumentDetectors.None,
    };

    /// <summary>The flags for a list of names: all for no list, null if any name is unknown.</summary>
    internal static ArgumentDetectors? Resolve(IReadOnlyList<string>? names)
    {
        if (names is null)
        {
            return ArgumentDetectors.All;
        }

        var flags = ArgumentDetectors.None;

        foreach (var name in names)
        {
            var flag = Parse(name);
            if (flag is ArgumentDetectors.None)
            {
                return null;
            }

            flags |= flag;
        }

        return flags;
    }

    /// <summary>What a detector's hit means, phrased to follow "the arguments contain".</summary>
    public static string Describe(string detector) => detector switch
    {
        Ssrf => "a URL pointing at an internal, loopback or cloud-metadata address",
        SensitivePath => "the location of a credential file",
        PathTraversal => "a path that climbs out of its directory with '..'",
        ShellMetachar => "shell metacharacters in a command argument",
        _ => "more data than the proxy inspects (too large or too deeply nested)",
    };
}

/// <summary>
/// The <c>scanners.arguments</c> section: built-in detection of attack shapes in
/// tool-call arguments.
/// </summary>
/// <remarks>
/// Unknown keys are refused, unlike most of the policy file, because every key
/// here is a security setting: a misspelt <c>acton: block</c> silently read as
/// the default <c>audit</c> would be the fail-open this section exists to avoid.
/// </remarks>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ArgumentScannerSettings
{
    /// <summary>The settings used when the policy file says nothing.</summary>
    public static ArgumentScannerSettings Default { get; } = new();

    /// <summary>Argument scanning off entirely.</summary>
    public static ArgumentScannerSettings Disabled { get; } = new() { Action = ArgumentAction.Off };

    /// <summary>What to do on a hit: <c>audit</c>, <c>approve</c>, <c>block</c> or <c>off</c>.</summary>
    [JsonPropertyName("action")]
    public ArgumentAction? Action { get; init; }

    /// <inheritdoc cref="Action" />
    [JsonIgnore]
    public ArgumentAction EffectiveAction => Action ?? ArgumentAction.Audit;

    /// <summary>Which detectors run. Absent means all of them; an empty list means none.</summary>
    [JsonPropertyName("detectors")]
    public IReadOnlyList<string>? Detectors
    {
        get => _detectors;
        init => (_detectors, _flags) = (value, ArgumentDetector.Resolve(value));
    }

    private readonly IReadOnlyList<string>? _detectors;

    // Resolved once, when the list is set, rather than on every call; null when
    // the list names something that is not a detector.
    private readonly ArgumentDetectors? _flags = ArgumentDetectors.All;

    /// <summary>
    /// Per-tool settings, matched as globs against the client-visible tool name.
    /// The first matching entry wins, as with rules.
    /// </summary>
    /// <remarks>
    /// The only way to exempt a tool. A policy rule that allows the call does not
    /// silence the detectors, because a broad allow rule written for convenience
    /// should not also switch off a security finding nobody was thinking about
    /// when they wrote it.
    /// </remarks>
    [JsonPropertyName("overrides")]
    public IReadOnlyList<ArgumentOverride>? Overrides { get; init; }

    /// <summary>The action and detectors that apply to one tool.</summary>
    /// <param name="toolName">Client-visible tool name.</param>
    /// <remarks>
    /// An override inherits what it does not say: <c>{tool, action: block}</c>
    /// blocks on every detector the section enables, and <c>{tool, detectors}</c>
    /// keeps the section's action.
    /// </remarks>
    public (ArgumentAction Action, ArgumentDetectors Detectors) For(string toolName)
    {
        ArgumentNullException.ThrowIfNull(toolName);

        var action = EffectiveAction;
        var detectors = Resolved(_flags);

        foreach (var entry in Overrides ?? [])
        {
            // Validated non-empty at load.
            if (GlobMatcher.IsMatch(entry.Tool!, toolName))
            {
                return (entry.Action ?? action, entry.Detectors is null ? detectors : Resolved(entry.Flags));
            }
        }

        return (action, detectors);
    }

    /// <remarks>
    /// An unknown name never quietly means "no detector": settings built in code
    /// skip the loader's validation, and reading the name as nothing would
    /// switch the check off without a word.
    /// </remarks>
    private static ArgumentDetectors Resolved(ArgumentDetectors? flags) =>
        flags ?? throw new PolicyException(
            "'scanners.arguments' names an unknown detector, so it cannot be applied. " +
            $"Use {string.Join(", ", ArgumentDetector.Configurable)}.");

    internal void Validate()
    {
        if (!Enum.IsDefined(EffectiveAction))
        {
            throw new PolicyException(
                "'scanners.arguments.action' is not a known action. Use audit, approve, block or off.");
        }

        ValidateDetectors(Detectors, "scanners.arguments.detectors");

        var index = 0;
        foreach (var entry in Overrides ?? [])
        {
            var where = $"scanners.arguments.overrides[{index++}]";

            if (entry is null || string.IsNullOrWhiteSpace(entry.Tool))
            {
                throw new PolicyException($"'{where}' needs 'tool:', the tool name or glob it applies to.");
            }

            if (entry.Action is { } action && !Enum.IsDefined(action))
            {
                throw new PolicyException($"'{where}.action' is not a known action. Use audit, approve, block or off.");
            }

            // An entry that changes nothing is almost certainly a mistake - most
            // likely a misindented key - and it would still shadow every entry
            // after it that matches the same tool.
            if (entry.Action is null && entry.Detectors is null)
            {
                throw new PolicyException($"'{where}' sets neither 'action:' nor 'detectors:', so it changes nothing.");
            }

            ValidateDetectors(entry.Detectors, $"{where}.detectors");
        }
    }

    private static void ValidateDetectors(IReadOnlyList<string>? names, string where)
    {
        foreach (var name in names ?? [])
        {
            if (name == ArgumentDetector.TooLarge)
            {
                throw new PolicyException(
                    $"'{where}' lists '{ArgumentDetector.TooLarge}', which is not a detector you can choose: " +
                    "it fires whenever the other detectors cannot read all of the arguments.");
            }

            if (ArgumentDetector.Parse(name) is ArgumentDetectors.None)
            {
                throw new PolicyException(
                    $"'{where}' lists unknown detector '{name}'. Use " +
                    $"{string.Join(", ", ArgumentDetector.Configurable)}.");
            }
        }
    }
}

/// <summary>One entry under <c>scanners.arguments.overrides</c>.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ArgumentOverride
{
    /// <summary>Client-visible tool name or glob, e.g. <c>fs__*</c>.</summary>
    [JsonPropertyName("tool")]
    public string? Tool { get; init; }

    /// <summary>The detectors for this tool. Absent means the section's.</summary>
    [JsonPropertyName("detectors")]
    public IReadOnlyList<string>? Detectors
    {
        get => _detectors;
        init => (_detectors, Flags) = (value, ArgumentDetector.Resolve(value));
    }

    private readonly IReadOnlyList<string>? _detectors;

    /// <summary><see cref="Detectors"/> resolved when set; null when it names an unknown detector.</summary>
    internal ArgumentDetectors? Flags { get; private init; } = ArgumentDetectors.All;

    /// <summary>The action for this tool. Absent means the section's.</summary>
    [JsonPropertyName("action")]
    public ArgumentAction? Action { get; init; }
}
