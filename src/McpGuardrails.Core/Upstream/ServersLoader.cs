using System.Text.Json;
using System.Text.Json.Nodes;
using McpGuardrails.Core.Serialization;

namespace McpGuardrails.Core.Upstream;

/// <summary>
/// What loading a servers file produced: the servers to connect, and everything
/// wrong with the file.
/// </summary>
/// <param name="Servers">Enabled servers, every value expanded, in file order.</param>
/// <param name="Disabled">Names of servers marked <c>disabled: true</c>.</param>
/// <param name="Warnings">Problems that do not stop the proxy starting.</param>
/// <param name="Errors">Problems that do; empty when the file is valid.</param>
public sealed record ServersLoadResult(
    IReadOnlyList<UpstreamServerConfig> Servers,
    IReadOnlyList<string> Disabled,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Errors)
{
    /// <summary>True when nothing stops the proxy from starting with this file.</summary>
    public bool IsValid => Errors.Count == 0;

    /// <summary>The servers, or a <see cref="ServersException"/> listing every error.</summary>
    /// <exception cref="ServersException">The file has at least one error.</exception>
    public IReadOnlyList<UpstreamServerConfig> EnsureValid() =>
        IsValid ? Servers : throw new ServersException(Errors);
}

/// <summary>A servers file the proxy refuses to start with.</summary>
/// <remarks>Carries every error, not only the first: fixing a config one restart at a time is miserable.</remarks>
public sealed class ServersException(IReadOnlyList<string> errors)
    : Exception(string.Join(Environment.NewLine, errors))
{
    /// <summary>Each problem, as one sentence naming the server and field.</summary>
    public IReadOnlyList<string> Errors { get; } = errors;
}

/// <summary>
/// Reads a servers file - the list of downstream MCP servers the proxy fronts -
/// into validated <see cref="UpstreamServerConfig"/>s.
/// </summary>
/// <remarks>
/// The policy file says what calls may do; this file says where they go. Kept
/// separate because they change for different reasons and are reviewed by
/// different people: adding a server is an operations change, loosening a rule
/// is a security one.
///
/// The format is deliberately the one users already have. <c>mcpServers</c> is
/// accepted as an alias of <c>servers</c>, and the per-server fields are the ones
/// Claude Desktop, Claude Code, Cursor and VS Code write, so most client configs
/// load as they are. Keys that only mean something to a client (a tool timeout,
/// an OAuth client id) are ignored with a warning. <b>Any other unknown key is an
/// error</b>: silently ignoring a misspelt security option is exactly the
/// fail-open this project exists to avoid.
///
/// Loading never stops at the first problem. Every error in the file is collected
/// and reported together, before anything is spawned.
///
/// <b>This file is code execution:</b> whoever can write it chooses what the
/// proxy launches. Hence no hot reload (changes take effect on a restart, which
/// is explicit and auditable) and the warning when it is group- or
/// world-writable.
/// </remarks>
public static partial class ServersLoader
{
    /// <summary>The only <c>version</c> this build understands.</summary>
    public const int CurrentVersion = 1;

    /// <summary>The environment variable naming the servers file.</summary>
    public const string FileVariable = "GUARDRAILS_SERVERS";

    /// <summary>
    /// Keys clients define for their own use. Accepted so a client's config loads
    /// unchanged, but they configure nothing here, and the warning says so.
    /// </summary>
    public static IReadOnlyList<string> ClientOnlyKeys { get; } =
        ["timeout", "alwaysLoad", "oauth", "auth", "headersHelper", "dev", "sandboxEnabled", "transportType"];

    private static readonly HashSet<string> _topLevelKeys =
        new(["version", "defaults", "servers", "mcpServers"], StringComparer.Ordinal);

    private static readonly HashSet<string> _defaultsKeys =
        new(["shutdown_timeout", "env_passthrough", "env_isolation"], StringComparer.Ordinal);

    private static readonly HashSet<string> _serverKeys = new(
        [
            "type", "command", "args", "env", "env_file", "envFile", "cwd", "url", "headers",
            "disabled", "optional", "shutdown_timeout", "env_passthrough", "env_isolation", "x-guardrails",
        ],
        StringComparer.Ordinal);

    /// <summary>
    /// Loads the servers file at <paramref name="path"/>. A missing file is an
    /// error: the caller decides whether a missing default file means "use the
    /// built-in server" before calling this.
    /// </summary>
    public static ServersLoadResult LoadFile(string path, HostEnvironment host)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(host);

        if (host.DirectoryExists(path))
        {
            return Failed($"Servers file '{path}' is a directory, not a file.");
        }

        if (!host.FileExists(path))
        {
            return Failed($"Servers file '{path}' does not exist.");
        }

        string text;
        try
        {
            text = host.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Failed($"Could not read servers file '{path}': {ex.Message}");
        }

        var fullPath = Path.GetFullPath(path);
        var result = Parse(text, Path.GetDirectoryName(fullPath)!, host);

        if (host.GetUnixFileMode(fullPath) is { } mode &&
            (mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
        {
            return result with
            {
                Warnings =
                [
                    .. result.Warnings,
                    $"Servers file '{path}' is writable by other users. Anyone who can write it chooses " +
                    "what the proxy launches; restrict it with 'chmod go-w'.",
                ],
            };
        }

        return result;
    }

    /// <summary>Parses and validates servers-file text (YAML or JSON).</summary>
    /// <param name="text">The file's contents.</param>
    /// <param name="baseDirectory">Where relative <c>cwd</c> and <c>env_file</c> paths start from.</param>
    /// <param name="host">The environment variables and file system to validate against.</param>
    public static ServersLoadResult Parse(string text, string baseDirectory, HostEnvironment host)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(baseDirectory);
        ArgumentNullException.ThrowIfNull(host);

        JsonNode? root;
        try
        {
            root = YamlJson.Parse(text);
        }
        catch (YamlJsonException ex)
        {
            return Failed(ex.Message);
        }

        var errors = new List<string>();
        var warnings = new List<string>();

        if (root is null)
        {
            warnings.Add("The servers file is empty, so the proxy will serve no tools.");
            return new ServersLoadResult([], [], warnings, errors);
        }

        if (root is not JsonObject document)
        {
            return Failed("The servers file must be a mapping with a 'servers' key.");
        }

        RejectUnknownKeys(document, _topLevelKeys, "at the top level", errors);
        CheckVersion(document["version"], errors, warnings);

        var defaults = ReadDefaults(document["defaults"], errors);

        var entries = new List<(string Name, JsonNode? Node)>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var section in new[] { "servers", "mcpServers" })
        {
            switch (document[section])
            {
                case null:
                    break;
                case JsonObject servers:
                    foreach (var (name, node) in servers)
                    {
                        if (seen.Add(name))
                        {
                            entries.Add((name, node));
                        }
                        else
                        {
                            errors.Add($"Server '{name}' is defined in both 'servers' and 'mcpServers'. Names must be unique.");
                        }
                    }

                    break;
                default:
                    errors.Add($"'{section}' must be a mapping of server names to servers.");
                    break;
            }
        }

        var configs = new List<UpstreamServerConfig>();
        var disabled = new List<string>();

        foreach (var (name, node) in entries)
        {
            var builder = new ServerBuilder(name, baseDirectory, host, defaults, errors, warnings);
            switch (builder.Build(node))
            {
                case { } config:
                    configs.Add(config);
                    break;
                case null when builder.IsDisabled:
                    disabled.Add(name);
                    break;
            }
        }

        if (errors.Count == 0 && configs.Count == 0)
        {
            warnings.Add("The servers file declares no enabled servers, so the proxy will serve no tools.");
        }

        return new ServersLoadResult(configs, disabled, warnings, errors);
    }

    private static ServersLoadResult Failed(string error) => new([], [], [], [error]);

    private static void RejectUnknownKeys(JsonObject node, HashSet<string> known, string where, List<string> errors)
    {
        foreach (var (key, _) in node)
        {
            if (!known.Contains(key))
            {
                errors.Add($"Unknown key '{key}' {where}.");
            }
        }
    }

    private static void CheckVersion(JsonNode? version, List<string> errors, List<string> warnings)
    {
        if (version is null)
        {
            warnings.Add($"The servers file has no 'version'; reading it as version {CurrentVersion}. Add 'version: {CurrentVersion}'.");
            return;
        }

        if (version is not JsonValue value || !value.TryGetValue<long>(out var number) || number != CurrentVersion)
        {
            errors.Add($"'version' must be {CurrentVersion}, the only version this build understands.");
        }
    }

    private static ServerDefaultsDocument ReadDefaults(JsonNode? node, List<string> errors)
    {
        if (node is null)
        {
            return new ServerDefaultsDocument();
        }

        if (node is not JsonObject defaults)
        {
            errors.Add("'defaults' must be a mapping.");
            return new ServerDefaultsDocument();
        }

        var before = errors.Count;
        RejectUnknownKeys(defaults, _defaultsKeys, "in 'defaults'", errors);
        if (errors.Count > before)
        {
            return new ServerDefaultsDocument();
        }

        try
        {
            return defaults.Deserialize(GuardrailsJsonContext.Default.ServerDefaultsDocument)!;
        }
        catch (JsonException ex)
        {
            errors.Add($"'defaults' is not valid: {ex.Message}");
            return new ServerDefaultsDocument();
        }
    }

    /// <summary>Joins a command line for display, quoting the arguments that need it.</summary>
    internal static string DisplayCommandLine(string command, IReadOnlyList<string> arguments) =>
        string.Join(' ', new[] { command }.Concat(arguments).Select(
            part => part.Length == 0 || part.Any(char.IsWhiteSpace) || part.Contains('"')
                ? $"\"{part.Replace("\"", "\\\"", StringComparison.Ordinal)}\""
                : part));
}
