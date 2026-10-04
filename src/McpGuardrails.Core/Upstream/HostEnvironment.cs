namespace McpGuardrails.Core.Upstream;

/// <summary>
/// What the servers loader and the client-config commands need from the machine:
/// environment variables and the file system.
/// </summary>
/// <remarks>
/// Passed in rather than read from <see cref="Environment"/> and
/// <see cref="File"/> directly, so every validation rule - an unset variable, a
/// command missing from PATH, a group-writable file - is a unit test with a
/// dictionary and a lambda instead of a test that mutates the real process
/// environment. The CLI builds the real one.
/// </remarks>
public sealed class HostEnvironment
{
    /// <summary>Reads one environment variable; null when unset.</summary>
    public required Func<string, string?> GetVariable { get; init; }

    /// <summary>Every environment variable name currently set.</summary>
    public required Func<IEnumerable<string>> VariableNames { get; init; }

    public required Func<string, bool> FileExists { get; init; }

    public required Func<string, bool> DirectoryExists { get; init; }

    /// <summary>Reads a file; may throw IOException or UnauthorizedAccessException.</summary>
    public required Func<string, string> ReadAllText { get; init; }

    /// <summary>A file's Unix permission bits, or null where there are none (Windows).</summary>
    public required Func<string, UnixFileMode?> GetUnixFileMode { get; init; }

    /// <summary>The user's home directory, for default paths.</summary>
    public required string HomeDirectory { get; init; }

    /// <summary>True on Windows: PATH uses ';' and commands may need a PATHEXT extension.</summary>
    public bool IsWindows { get; init; }

    /// <summary>True on macOS, where clients keep their config under ~/Library.</summary>
    public bool IsMacOS { get; init; }
}
