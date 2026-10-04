using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Tests.Upstream;

/// <summary>
/// An in-memory machine for the servers loader: environment variables, files and
/// directories as dictionaries, so every rule is testable without touching the
/// real environment.
/// </summary>
/// <remarks>
/// Paths are built with <see cref="At"/> so they are absolute on every platform
/// the tests run on, Windows included, and PATH uses the platform's separator.
/// </remarks>
internal sealed class FakeHost
{
    /// <summary>The root every fake path hangs off.</summary>
    public static readonly string Root = OperatingSystem.IsWindows() ? @"C:\" : "/";

    /// <summary>The fake bin directory on PATH.</summary>
    public static readonly string Bin = At("usr", "bin");

    public FakeHost()
    {
        Variables["PATH"] = Bin;
        Variables["HOME"] = Home;
        foreach (var command in new[] { "npx", "python3", "uvx", "docker" })
        {
            // On Windows a bare name only resolves with a PATHEXT extension, as there.
            Files.Add(Path.Combine(Bin, OperatingSystem.IsWindows() ? command + ".exe" : command));
        }

        Directories.Add(Home);
    }

    public static string Home { get; } = At("home", "user");

    public Dictionary<string, string> Variables { get; } = new(StringComparer.Ordinal);

    public HashSet<string> Files { get; } = new(StringComparer.OrdinalIgnoreCase);

    public HashSet<string> Directories { get; } = new(StringComparer.Ordinal);

    public Dictionary<string, string> Contents { get; } = new(StringComparer.Ordinal);

    public Dictionary<string, UnixFileMode> Modes { get; } = new(StringComparer.Ordinal);

    /// <summary>Paths whose read throws, and what it throws.</summary>
    public Dictionary<string, Exception> Unreadable { get; } = new(StringComparer.Ordinal);

    public bool IsWindows { get; init; } = OperatingSystem.IsWindows();

    public bool IsMacOS { get; init; }

    /// <summary>What the host reports as the proxy's <c>uid:gid</c>; null when it cannot say.</summary>
    public string? UserAndGroup { get; set; } = "1000:1000";

    /// <summary>Puts <paramref name="command"/> on the fake PATH.</summary>
    public FakeHost WithCommand(string command)
    {
        Files.Add(Path.Combine(Bin, OperatingSystem.IsWindows() ? command + ".exe" : command));
        return this;
    }

    /// <summary>Takes <paramref name="command"/> off the fake PATH.</summary>
    public FakeHost WithoutCommand(string command)
    {
        Files.Remove(Path.Combine(Bin, OperatingSystem.IsWindows() ? command + ".exe" : command));
        return this;
    }

    public static string At(params string[] parts) => Path.Combine([Root, .. parts]);

    public HostEnvironment Build() => new()
    {
        GetVariable = name => Variables.GetValueOrDefault(name),
        VariableNames = () => Variables.Keys,
        FileExists = path => Files.Contains(path) || Contents.ContainsKey(path),
        DirectoryExists = Directories.Contains,
        ReadAllText = path => Unreadable.TryGetValue(path, out var failure)
            ? throw failure
            : Contents.TryGetValue(path, out var text)
                ? text
                : throw new FileNotFoundException($"Could not find file '{path}'.", path),
        GetUnixFileMode = path => Modes.TryGetValue(path, out var mode) ? mode : null,
        HomeDirectory = Home,
        IsWindows = IsWindows,
        IsMacOS = IsMacOS,
        UserAndGroup = () => UserAndGroup,
    };
}
