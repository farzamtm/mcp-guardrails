using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Upstream;

/// <summary>
/// Decides which of the proxy's environment variables a stdio child may see.
/// </summary>
/// <remarks>
/// A child process normally inherits its parent's whole environment. For this
/// proxy that environment holds <c>ANTHROPIC_API_KEY</c> for the classifier,
/// <c>GUARDRAILS_HTTP_TOKEN</c>, the webhook signing secret and - once several
/// servers are configured - every other server's token. Handing all of it to a
/// downstream server that is, by this project's own threat model, possibly
/// hostile, is the opposite of least privilege.
///
/// Under isolation a child gets a short built-in list of variables that programs
/// need simply to run (PATH to find their interpreter, HOME for their config, the
/// temp directory, the Windows system paths), plus whatever the servers file
/// passes through by name, plus its own <c>env</c>. Nothing else.
/// </remarks>
public static class EnvironmentIsolation
{
    /// <summary>
    /// Variables every isolated child gets, when the proxy has them set.
    /// </summary>
    /// <remarks>
    /// Compared case-insensitively because Windows environment names are (it
    /// spells PATH as "Path"); on Unix nothing sets "path", so this costs nothing.
    /// </remarks>
    public static IReadOnlyList<string> Allowlist { get; } =
    [
        "PATH", "HOME", "USER", "LANG", "TMPDIR", "TEMP", "TMP",
        "USERPROFILE", "APPDATA", "LOCALAPPDATA", "SystemRoot", "ComSpec", "PATHEXT",
    ];

    /// <summary>
    /// The passthrough entry that turns isolation off again: every variable is
    /// passed on.
    /// </summary>
    public const string Everything = "*";

    /// <summary>
    /// The names a child may inherit: on the allowlist, or matching one of
    /// <paramref name="passthrough"/>.
    /// </summary>
    /// <param name="name">An environment variable name.</param>
    /// <param name="passthrough">
    /// Names or globs from <c>env_passthrough</c>, matched case-sensitively like
    /// every other glob in the proxy.
    /// </param>
    public static bool IsPassed(string name, IReadOnlyList<string> passthrough)
    {
        foreach (var allowed in Allowlist)
        {
            if (string.Equals(name, allowed, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        foreach (var pattern in passthrough)
        {
            if (GlobMatcher.IsMatch(pattern, name))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// The complete environment of an isolated child.
    /// </summary>
    /// <param name="host">Where the proxy's own variables come from.</param>
    /// <param name="passthrough">Extra names or globs to pass on.</param>
    /// <param name="own">The server's own <c>env</c>, which wins over anything inherited.</param>
    public static Dictionary<string, string?> ChildEnvironment(
        HostEnvironment host,
        IReadOnlyList<string> passthrough,
        IReadOnlyDictionary<string, string?> own)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(passthrough);
        ArgumentNullException.ThrowIfNull(own);

        var environment = new Dictionary<string, string?>(StringComparer.Ordinal);

        foreach (var name in host.VariableNames())
        {
            if (IsPassed(name, passthrough) && host.GetVariable(name) is { } value)
            {
                environment[name] = value;
            }
        }

        foreach (var (name, value) in own)
        {
            environment[name] = value;
        }

        return environment;
    }

    /// <summary>
    /// The variables a child inherits today that isolation would withhold, sorted:
    /// names only, never values.
    /// </summary>
    /// <remarks>
    /// For the one-release warning before isolation becomes the default. Seeing
    /// the actual list ("ANTHROPIC_API_KEY, AWS_SECRET_ACCESS_KEY, ...") is what
    /// turns an abstract notice into a reason to set <c>env_isolation: true</c>
    /// today - and tells the operator what to pass through if a server needs one.
    /// </remarks>
    public static IReadOnlyList<string> WouldWithhold(
        HostEnvironment host,
        IReadOnlyList<string> passthrough,
        IReadOnlyDictionary<string, string?> own)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(passthrough);
        ArgumentNullException.ThrowIfNull(own);

        return
        [
            .. host.VariableNames()
                .Where(name => !IsPassed(name, passthrough) && !own.ContainsKey(name))
                .Order(StringComparer.Ordinal),
        ];
    }
}
