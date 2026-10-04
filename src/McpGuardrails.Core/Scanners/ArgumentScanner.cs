using System.Text;
using System.Text.Json;

namespace McpGuardrails.Core.Scanners;

/// <summary>One detector's first hit in a call.</summary>
/// <param name="Detector">The detector's name, e.g. <c>ssrf</c>.</param>
/// <param name="Argument">
/// Where it was found, e.g. <c>url</c> or <c>options.paths[2]</c>; empty for
/// <see cref="ArgumentDetector.TooLarge"/>, which is about the call as a whole.
/// </param>
public sealed record ArgumentHit(string Detector, string Argument);

/// <summary>What the argument detectors found in one call.</summary>
/// <param name="Hits">At most one hit per detector, in reporting order.</param>
/// <remarks>
/// Names and argument paths only, never the values. The value is exactly the
/// part an attacker chose, and it is shown where it belongs - in the call's own
/// arguments, which the audit log and an approver already see with secrets
/// redacted - rather than copied into a field that reads as the proxy's own
/// words.
/// </remarks>
public sealed record ArgumentFindings(IReadOnlyList<ArgumentHit> Hits)
{
    /// <summary>Nothing found.</summary>
    public static ArgumentFindings Clean { get; } = new([]);

    /// <summary>True when no detector fired.</summary>
    public bool IsClean => Hits.Count == 0;

    /// <summary>The names of the detectors that fired, for the audit log.</summary>
    public IReadOnlyList<string> Detectors => [.. Hits.Select(hit => hit.Detector)];

    /// <summary>"ssrf in 'url', path-traversal in 'path'", for messages.</summary>
    public string Summary => string.Join(", ", Hits.Select(hit =>
        hit.Argument.Length == 0 ? hit.Detector : $"{hit.Detector} in '{hit.Argument}'"));
}

/// <summary>
/// Runs the argument detectors over every string in a call's arguments.
/// </summary>
/// <remarks>
/// Recursive over nested objects and arrays, because a URL inside
/// <c>{"request": {"target": ...}}</c> is fetched just the same. Capped in depth,
/// node count and total characters, and <b>hitting a cap is itself a finding</b>
/// (<see cref="ArgumentDetector.TooLarge"/>) rather than a reason to stop
/// looking quietly: otherwise the way past the detectors would be to put the
/// payload after a few megabytes of padding.
///
/// Every detector is linear in the string it reads, and every string is read a
/// bounded number of times, so the whole scan is linear in the size of the
/// arguments.
/// </remarks>
public static class ArgumentScanner
{
    /// <summary>Deepest nesting inspected; the JSON reader's own default limit.</summary>
    public const int MaxDepth = 64;

    /// <summary>
    /// Most characters inspected across every key and string in one call.
    /// </summary>
    /// <remarks>
    /// Comfortably above the 10 MB a single argument might plausibly carry - a
    /// file being written, say - so ordinary large calls are scanned in full and
    /// only something larger is reported as uninspectable.
    /// </remarks>
    public const int MaxCharacters = 16 * 1024 * 1024;

    /// <summary>Most values inspected in one call.</summary>
    public const int MaxValues = 1_000_000;

    private const int _maxArgumentPathLength = 80;

    private static readonly string[] _reportingOrder = [.. ArgumentDetector.Configurable, ArgumentDetector.TooLarge];

    /// <summary>Scans a call's arguments with the given detectors.</summary>
    /// <param name="toolName">Client-visible tool name; decides whether every string is a command.</param>
    /// <param name="arguments">The arguments as the model sent them.</param>
    /// <param name="detectors">Which detectors to run.</param>
    public static ArgumentFindings Scan(
        string toolName,
        IEnumerable<KeyValuePair<string, JsonElement>>? arguments,
        ArgumentDetectors detectors)
    {
        ArgumentNullException.ThrowIfNull(toolName);

        if (arguments is null || detectors is ArgumentDetectors.None)
        {
            return ArgumentFindings.Clean;
        }

        var walk = new Walk(detectors, IsShellTool(toolName));

        foreach (var (name, value) in arguments)
        {
            if (!walk.Property(name, value, depth: 1, Context.None))
            {
                break;
            }
        }

        return walk.Findings();
    }

    /// <summary>
    /// True for a tool named like one that runs what it is given in a shell.
    /// </summary>
    /// <remarks>
    /// Names, because MCP has no annotation that says "this runs a shell". Every
    /// string argument of such a tool is treated as a command.
    /// </remarks>
    internal static bool IsShellTool(string toolName) =>
        toolName.Contains("exec", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("shell", StringComparison.OrdinalIgnoreCase) ||
        toolName.Contains("run_command", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True when a string argument holds shell metacharacters.
    /// </summary>
    /// <remarks>
    /// Command separators and chaining (<c>; | &amp;</c>, newlines), command
    /// substitution (<c>`</c>, <c>$(</c>) and parameter expansion (<c>${</c>), and
    /// redirection (<c>&gt; &lt;</c>). Each turns "run this program" into "run
    /// this program, and also whatever comes next".
    /// </remarks>
    internal static bool HasShellMetacharacters(string value)
    {
        for (var i = 0; i < value.Length; i++)
        {
            switch (value[i])
            {
                case ';' or '|' or '&' or '`' or '>' or '<' or '\n' or '\r':
                    return true;
                case '$' when i + 1 < value.Length && value[i + 1] is '(' or '{':
                    return true;
            }
        }

        return false;
    }

    [Flags]
    private enum Context
    {
        None = 0,

        /// <summary>The nearest property name says it is a command.</summary>
        Command = 1,

        /// <summary>The nearest property name says it is a path.</summary>
        Path = 2,
    }

    private static readonly HashSet<string> _commandWords = new(StringComparer.Ordinal)
    {
        "command", "cmd", "script", "shell", "exec", "args", "argv",
    };

    private static readonly HashSet<string> _pathWords = new(StringComparer.Ordinal)
    {
        "path", "file", "filename", "filepath", "dir", "directory", "folder", "src", "source", "dest",
        "destination", "target",
    };

    /// <summary>What a property's name says about its value.</summary>
    /// <remarks>
    /// Split into words on punctuation and camel case, so <c>shell_command</c>,
    /// <c>commandLine</c> and <c>sourcePaths</c> are recognised as well as the
    /// bare words. A trailing <c>s</c> is ignored, for lists.
    /// </remarks>
    private static Context Classify(string name)
    {
        var context = Context.None;
        var start = 0;

        for (var i = 1; i <= name.Length; i++)
        {
            if (i < name.Length && char.IsLetterOrDigit(name[i]) &&
                !(char.IsUpper(name[i]) && char.IsLower(name[i - 1])))
            {
                continue;
            }

            var word = name[start..i].Trim('_', '-', '.', ' ').ToLowerInvariant();
            var singular = word.EndsWith('s') ? word[..^1] : word;

            if (_commandWords.Contains(word) || _commandWords.Contains(singular))
            {
                context |= Context.Command;
            }

            if (_pathWords.Contains(word) || _pathWords.Contains(singular))
            {
                context |= Context.Path;
            }

            start = i;
        }

        return context;
    }

    /// <summary>The state of one scan.</summary>
    private sealed class Walk(ArgumentDetectors detectors, bool shellTool)
    {
        private readonly Dictionary<string, string> _hits = new(StringComparer.Ordinal);
        private readonly List<string> _path = [];
        private long _characters;
        private int _values;

        /// <summary>Scans one named value. Returns false once a cap is hit and scanning must stop.</summary>
        public bool Property(string name, JsonElement value, int depth, Context inherited)
        {
            if (!Charge(name.Length))
            {
                return false;
            }

            // The nearest name wins for what it says, but a value nested under a
            // command keeps being a command: {"command": {"argv": [...]}}.
            var context = Classify(name) | (inherited & Context.Command);

            _path.Add(_path.Count == 0 ? name : "." + name);
            var more = Value(value, depth, context);
            _path.RemoveAt(_path.Count - 1);

            return more;
        }

        private bool Value(JsonElement value, int depth, Context context)
        {
            if (depth > MaxDepth || !Charge(0))
            {
                return Stop();
            }

            switch (value.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var property in value.EnumerateObject())
                    {
                        if (!Property(property.Name, property.Value, depth + 1, context))
                        {
                            return false;
                        }
                    }

                    return true;

                case JsonValueKind.Array:
                    var index = 0;
                    foreach (var item in value.EnumerateArray())
                    {
                        _path.Add($"[{index++}]");
                        var more = Value(item, depth + 1, context);
                        _path.RemoveAt(_path.Count - 1);

                        if (!more)
                        {
                            return false;
                        }
                    }

                    return true;

                case JsonValueKind.String:
                    var text = value.GetString()!;
                    if (!Charge(text.Length))
                    {
                        return false;
                    }

                    Inspect(text, context);
                    return true;

                default:
                    // Numbers, booleans and null carry no URL, path or command.
                    return true;
            }
        }

        private void Inspect(string text, Context context)
        {
            if (detectors.HasFlag(ArgumentDetectors.Ssrf) && SsrfDetector.IsMatch(text))
            {
                Hit(ArgumentDetector.Ssrf);
            }

            if (detectors.HasFlag(ArgumentDetectors.SensitivePath) &&
                PathDetectors.IsSensitivePath(text, context.HasFlag(Context.Path)))
            {
                Hit(ArgumentDetector.SensitivePath);
            }

            if (detectors.HasFlag(ArgumentDetectors.PathTraversal) && PathDetectors.HasTraversal(text))
            {
                Hit(ArgumentDetector.PathTraversal);
            }

            if (detectors.HasFlag(ArgumentDetectors.ShellMetachar) &&
                (shellTool || context.HasFlag(Context.Command)) &&
                HasShellMetacharacters(text))
            {
                Hit(ArgumentDetector.ShellMetachar);
            }
        }

        /// <summary>Counts characters and values against the caps.</summary>
        private bool Charge(int characters)
        {
            _characters += characters;
            _values++;

            return (_characters <= MaxCharacters && _values <= MaxValues) || Stop();
        }

        private bool Stop()
        {
            _hits.TryAdd(ArgumentDetector.TooLarge, "");
            return false;
        }

        private void Hit(string detector)
        {
            // The first place each detector fired is enough to act on and to tell
            // a human where to look; a thousand internal URLs in one array should
            // not become a thousand-entry message.
            if (_hits.ContainsKey(detector))
            {
                return;
            }

            var path = new StringBuilder();
            foreach (var segment in _path)
            {
                path.Append(segment);
            }

            var text = path.ToString();
            _hits[detector] = text.Length > _maxArgumentPathLength ? text[.._maxArgumentPathLength] + "…" : text;
        }

        public ArgumentFindings Findings()
        {
            if (_hits.Count == 0)
            {
                return ArgumentFindings.Clean;
            }

            List<ArgumentHit> hits = [];
            foreach (var detector in _reportingOrder)
            {
                if (_hits.TryGetValue(detector, out var argument))
                {
                    hits.Add(new ArgumentHit(detector, argument));
                }
            }

            return new ArgumentFindings(hits);
        }
    }
}
