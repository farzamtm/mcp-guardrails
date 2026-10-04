using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using McpGuardrails.Core.Scanners;

namespace McpGuardrails.Core.Upstream;

/// <summary>An MCP client whose config file <c>import</c> and <c>wrap</c> understand.</summary>
public enum McpClientKind
{
    ClaudeDesktop,
    ClaudeCode,
    Cursor,
    VsCode,
}

/// <summary>Where a client keeps its MCP servers, and how it spells them.</summary>
/// <param name="Kind">The client.</param>
/// <param name="Name">Its name on the command line, e.g. <c>claude-desktop</c>.</param>
/// <param name="ServersKey">The JSON key holding the server map.</param>
/// <param name="StdioNeedsType">Whether the client wants <c>"type": "stdio"</c> written out.</param>
public sealed record ClientApp(McpClientKind Kind, string Name, string ServersKey, bool StdioNeedsType);

/// <summary>A value <c>import</c> moved out of the config and into a variable.</summary>
/// <param name="Variable">The variable the servers file now references.</param>
/// <param name="Value">The secret itself. Never written to the servers file.</param>
/// <param name="Server">The server it belonged to.</param>
/// <param name="Field">Where it was, e.g. <c>env.GITHUB_TOKEN</c>.</param>
public sealed record LiftedSecret(string Variable, string Value, string Server, string Field);

/// <summary>What <c>import</c> produced.</summary>
/// <param name="ServersYaml">The servers file, ready to write.</param>
/// <param name="ServerCount">How many servers it declares.</param>
/// <param name="Secrets">Values replaced by variable references, for the caller to hand back to the user.</param>
/// <param name="Notes">Renames, dropped keys and other things the user should know.</param>
public sealed record ImportResult(
    string ServersYaml,
    int ServerCount,
    IReadOnlyList<LiftedSecret> Secrets,
    IReadOnlyList<string> Notes);

/// <summary>A client config that cannot be imported or wrapped as it stands.</summary>
public sealed class ClientConfigException(string message) : Exception(message);

/// <summary>
/// Reads the MCP server lists of Claude Desktop, Claude Code, Cursor and VS Code,
/// and turns them into a servers file.
/// </summary>
/// <remarks>
/// Pure functions over strings; <see cref="ClientConfigFiles"/> is the thin layer
/// that touches the disk. That split is what lets every format quirk be a unit
/// test with a sample config rather than a test that edits real client files.
///
/// The one table of client locations is <see cref="DefaultPaths"/>. It was
/// checked against each client's documentation when written; when a client moves
/// its file, that method is the only place to change.
/// </remarks>
public static class ClientConfigs
{
    /// <summary>The name of the single entry <c>wrap</c> leaves in a client's server list.</summary>
    public const string WrappedEntryName = "guardrails";

    /// <summary>Every supported client, in the order they are listed in help text.</summary>
    public static IReadOnlyList<ClientApp> All { get; } =
    [
        new(McpClientKind.ClaudeDesktop, "claude-desktop", "mcpServers", StdioNeedsType: false),
        new(McpClientKind.ClaudeCode, "claude-code", "mcpServers", StdioNeedsType: false),
        new(McpClientKind.Cursor, "cursor", "mcpServers", StdioNeedsType: true),
        new(McpClientKind.VsCode, "vscode", "servers", StdioNeedsType: true),
    ];

    /// <summary>The client named <paramref name="name"/> on the command line, or null.</summary>
    public static ClientApp? Find(string name) =>
        All.FirstOrDefault(client => string.Equals(client.Name, name, StringComparison.Ordinal));

    /// <summary>
    /// Where a client's config may be, most specific first.
    /// </summary>
    /// <remarks>
    /// Project files come before user files, because a command run inside a
    /// project is about that project. Sources, as of 2026-10:
    ///
    /// - Claude Desktop: <c>~/Library/Application Support/Claude/claude_desktop_config.json</c>
    ///   on macOS, <c>%APPDATA%\Claude\claude_desktop_config.json</c> on Windows;
    ///   there is no Linux build (modelcontextprotocol.io, "Connect to local MCP servers").
    /// - Claude Code: <c>.mcp.json</c> in the project (top-level <c>mcpServers</c>),
    ///   and <c>~/.claude.json</c>, whose top-level <c>mcpServers</c> is the user
    ///   scope (code.claude.com, "MCP").
    /// - Cursor: <c>.cursor/mcp.json</c> in the project, <c>~/.cursor/mcp.json</c>
    ///   globally, both <c>mcpServers</c> (cursor.com, "Model Context Protocol").
    /// - VS Code: <c>.vscode/mcp.json</c> in the workspace and <c>mcp.json</c> in the
    ///   user profile folder, both keyed <c>servers</c> (code.visualstudio.com, "MCP
    ///   configuration reference").
    /// </remarks>
    /// <param name="client">The client.</param>
    /// <param name="host">For the home directory, APPDATA and the platform.</param>
    /// <param name="workingDirectory">The project directory.</param>
    public static IReadOnlyList<string> DefaultPaths(ClientApp client, HostEnvironment host, string workingDirectory)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(workingDirectory);

        var home = host.HomeDirectory;
        var appData = host.GetVariable("APPDATA") ?? Path.Combine(home, "AppData", "Roaming");

        // Folders under the user's profile where Electron apps keep their data.
        var userData = host.IsWindows
            ? appData
            : host.IsMacOS
                ? Path.Combine(home, "Library", "Application Support")
                : Path.Combine(home, ".config");

        return client.Kind switch
        {
            McpClientKind.ClaudeDesktop => host.IsWindows || host.IsMacOS
                ? [Path.Combine(userData, "Claude", "claude_desktop_config.json")]
                : [],
            McpClientKind.ClaudeCode =>
                [Path.Combine(workingDirectory, ".mcp.json"), Path.Combine(home, ".claude.json")],
            McpClientKind.Cursor =>
                [Path.Combine(workingDirectory, ".cursor", "mcp.json"), Path.Combine(home, ".cursor", "mcp.json")],
            _ =>
                [Path.Combine(workingDirectory, ".vscode", "mcp.json"), Path.Combine(userData, "Code", "User", "mcp.json")],
        };
    }

    /// <summary>
    /// Reads a client config's server list and writes it as a servers file.
    /// </summary>
    /// <param name="client">Which client wrote <paramref name="configText"/>.</param>
    /// <param name="configText">The client's config file.</param>
    /// <param name="configPath">Its path, for <c>${workspaceFolder}</c> and messages.</param>
    /// <param name="host">For <c>${userHome}</c>.</param>
    /// <remarks>
    /// <b>No secret from the config is written to the servers file.</b> Anything
    /// the secret scanner recognises - by shape, or by a key such as
    /// <c>API_KEY</c> or <c>Authorization</c> - is replaced with a
    /// <c>${SERVER_KEY}</c> reference and returned in
    /// <see cref="ImportResult.Secrets"/>, so the caller can tell the user once
    /// and put it in the environment instead. A servers file is meant to be
    /// committed and reviewed; a token in it would be committed too.
    /// </remarks>
    /// <exception cref="ClientConfigException">The config is not JSON, or has no server map.</exception>
    public static ImportResult Import(ClientApp client, string configText, string configPath, HostEnvironment host)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(configText);
        ArgumentNullException.ThrowIfNull(configPath);
        ArgumentNullException.ThrowIfNull(host);

        var servers = ReadServers(client, configText, configPath);

        var notes = new List<string>();
        var secrets = new List<LiftedSecret>();
        var usedNames = new HashSet<string>(StringComparer.Ordinal);
        var usedVariables = new HashSet<string>(StringComparer.Ordinal);
        var substitutions = Substitutions(configPath, host);

        var yaml = new StringBuilder();
        yaml.Append("# Imported by 'mcp-guardrails import' from ").Append(client.Name).Append(" (")
            .Append(configPath.Replace('\n', ' ')).Append(").\n");
        yaml.Append("version: 1\n");
        yaml.Append(servers.Count == 0 ? "servers: {}\n" : "servers:\n");

        foreach (var (originalName, node) in servers)
        {
            var name = UniqueName(SanitizeName(originalName), usedNames);
            if (name != originalName)
            {
                notes.Add($"Renamed server '{originalName}' to '{name}': names may only use letters, digits and hyphens.");
            }

            if (node is not JsonObject entry)
            {
                notes.Add($"Skipped server '{originalName}': its entry is not an object.");
                continue;
            }

            var context = new EntryContext(name, substitutions, usedVariables, secrets, notes);
            yaml.Append("  ").Append(name).Append(":\n");
            WriteEntry(entry, context, yaml);
        }

        return new ImportResult(yaml.ToString(), servers.Count(s => s.Node is JsonObject), secrets, notes);
    }

    /// <summary>
    /// The client config with its whole server list replaced by one entry that
    /// launches the proxy.
    /// </summary>
    /// <param name="client">Which client wrote <paramref name="configText"/>.</param>
    /// <param name="configText">The client's config file.</param>
    /// <param name="configPath">Its path, for messages.</param>
    /// <param name="binaryPath">The absolute path of the proxy executable.</param>
    /// <param name="serversPath">The absolute path of the servers file the proxy will read.</param>
    /// <param name="policyPath">The absolute path of the policy file the proxy will read.</param>
    /// <param name="secrets">What <see cref="Import"/> lifted; their values go into the entry's env.</param>
    /// <remarks>
    /// Every other key in the file is kept. The lifted secrets go into the new
    /// entry's <c>env</c>, which is where they already were - in this same file -
    /// so nothing is exposed that was not exposed before, and the proxy hands
    /// each one to the server whose servers-file entry references it.
    /// </remarks>
    /// <exception cref="ClientConfigException">
    /// The config cannot be wrapped: it is already wrapped, has no servers, or is
    /// <c>~/.claude.json</c>, which Claude Code rewrites constantly.
    /// </exception>
    public static string Wrap(
        ClientApp client,
        string configText,
        string configPath,
        string binaryPath,
        string serversPath,
        string policyPath,
        IReadOnlyList<LiftedSecret> secrets)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(configText);
        ArgumentNullException.ThrowIfNull(configPath);
        ArgumentNullException.ThrowIfNull(secrets);

        // ~/.claude.json holds Claude Code's whole state - history, trust
        // decisions, per-project settings - and Claude Code rewrites it as it
        // runs. Any restore from a backup would roll all of that back, and the
        // "has it changed since wrap?" check would fail every time.
        if (string.Equals(Path.GetFileName(configPath), ".claude.json", StringComparison.Ordinal))
        {
            throw new ClientConfigException(
                $"'{configPath}' holds Claude Code's own state and changes constantly, so it cannot be wrapped " +
                "and restored safely. Wrap a project's .mcp.json instead (run the command in that project).");
        }

        var root = ParseRoot(configText, configPath);
        var servers = root[client.ServersKey] as JsonObject;

        if (servers is null || servers.Count == 0)
        {
            throw new ClientConfigException($"'{configPath}' has no servers under '{client.ServersKey}', so there is nothing to wrap.");
        }

        if (servers.ContainsKey(WrappedEntryName))
        {
            throw new ClientConfigException(
                $"'{configPath}' already has a '{WrappedEntryName}' server. Run 'unwrap' first, or remove that entry.");
        }

        var env = new JsonObject
        {
            [ServersLoader.FileVariable] = serversPath,
            ["GUARDRAILS_POLICY"] = policyPath,
        };
        foreach (var secret in secrets)
        {
            env[secret.Variable] = secret.Value;
        }

        var entry = new JsonObject();
        if (client.StdioNeedsType)
        {
            entry["type"] = "stdio";
        }

        entry["command"] = binaryPath;
        entry["args"] = new JsonArray();
        entry["env"] = env;

        root[client.ServersKey] = new JsonObject { [WrappedEntryName] = entry };

        return WriteJson(root);
    }

    /// <summary>Lowercases nothing; replaces every character a server name may not use with '-'.</summary>
    internal static string SanitizeName(string name)
    {
        var builder = new StringBuilder(name.Length);
        foreach (var c in name)
        {
            var legal = char.IsAsciiLetterOrDigit(c) || c == '-';
            if (legal || (builder.Length > 0 && builder[^1] != '-'))
            {
                builder.Append(legal ? c : '-');
            }
        }

        var result = builder.ToString().Trim('-');
        return result.Length == 0 ? "server" : result;
    }

    private static string UniqueName(string name, HashSet<string> used)
    {
        var candidate = name;
        for (var suffix = 2; !used.Add(candidate); suffix++)
        {
            candidate = $"{name}-{suffix}";
        }

        return candidate;
    }

    private static JsonObject ParseRoot(string configText, string configPath)
    {
        JsonNode? root;
        try
        {
            // VS Code's mcp.json is JSON with comments and trailing commas.
            root = JsonNode.Parse(
                configText,
                documentOptions: new JsonDocumentOptions
                {
                    CommentHandling = JsonCommentHandling.Skip,
                    AllowTrailingCommas = true,
                });
        }
        catch (JsonException ex)
        {
            throw new ClientConfigException($"'{configPath}' is not valid JSON: {ex.Message}");
        }

        return root as JsonObject
               ?? throw new ClientConfigException($"'{configPath}' is not a JSON object.");
    }

    private static List<(string Name, JsonNode? Node)> ReadServers(ClientApp client, string configText, string configPath)
    {
        var root = ParseRoot(configText, configPath);

        return root[client.ServersKey] switch
        {
            null => [],
            JsonObject servers => [.. servers.Select(pair => (pair.Key, pair.Value))],
            _ => throw new ClientConfigException($"'{client.ServersKey}' in '{configPath}' is not an object."),
        };
    }

    /// <summary>
    /// The client-defined variables a servers file has no equivalent for,
    /// resolved now: the proxy does not run inside a workspace.
    /// </summary>
    private static Dictionary<string, string> Substitutions(string configPath, HostEnvironment host)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(configPath))!;

        // .cursor/mcp.json and .vscode/mcp.json live one level below the
        // workspace; .mcp.json lives in it.
        var workspace = Path.GetFileName(directory) is ".cursor" or ".vscode"
            ? Path.GetDirectoryName(directory)!
            : directory;

        var separator = host.IsWindows ? "\\" : "/";

        return new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["${userHome}"] = host.HomeDirectory,
            ["${workspaceFolder}"] = workspace,
            ["${workspaceFolderBasename}"] = Path.GetFileName(workspace),
            ["${pathSeparator}"] = separator,
            ["${/}"] = separator,
        };
    }

    private sealed record EntryContext(
        string Name,
        Dictionary<string, string> Substitutions,
        HashSet<string> UsedVariables,
        List<LiftedSecret> Secrets,
        List<string> Notes);

    private static readonly HashSet<string> _importedKeys = new(
        ["type", "command", "args", "env", "envFile", "env_file", "cwd", "url", "headers", "disabled"],
        StringComparer.Ordinal);

    private static void WriteEntry(JsonObject entry, EntryContext context, StringBuilder yaml)
    {
        var dropped = entry.Select(pair => pair.Key).Where(key => !_importedKeys.Contains(key)).ToList();
        if (dropped.Count > 0)
        {
            context.Notes.Add(
                $"Server '{context.Name}': dropped {string.Join(", ", dropped.Select(k => $"'{k}'"))}, " +
                "which configure the client rather than the server.");
        }

        var type = Text(entry["type"]);
        var url = entry["url"];

        switch (type)
        {
            case null or "stdio":
                if (url is not null)
                {
                    // Cursor writes remote servers as a bare url.
                    context.Notes.Add($"Server '{context.Name}' has a url and no type; imported as Streamable HTTP ('type: http').");
                    Field(yaml, "type", "http");
                }

                break;
            case "streamable-http":
                Field(yaml, "type", "http");
                break;
            default:
                Field(yaml, "type", type);
                break;
        }

        var command = Text(entry["command"]);
        if (command is not null)
        {
            Field(yaml, "command", Value(context, command, "command", propertyName: null));
        }

        if (entry["args"] is JsonArray args)
        {
            var values = args.Select((arg, i) => Value(context, Text(arg) ?? string.Empty, $"args[{i}]", propertyName: null)).ToList();
            yaml.Append("    args: [").AppendJoin(", ", values.Select(Quote)).Append("]\n");

            if (command is not null && PackageRunners.FindUnpinned(command, [.. args.Select(a => Text(a) ?? string.Empty)]) is { } package)
            {
                context.Notes.Add($"Server '{context.Name}' runs '{package}' without a pinned version; consider pinning it.");
            }
        }

        Map(yaml, context, entry["env"], "env");

        if (Text(entry["envFile"] ?? entry["env_file"]) is { } envFile)
        {
            Field(yaml, "env_file", Value(context, envFile, "env_file", propertyName: null));
        }

        if (Text(entry["cwd"]) is { } cwd)
        {
            Field(yaml, "cwd", Value(context, cwd, "cwd", propertyName: null));
        }

        if (Text(url) is { } urlText)
        {
            Field(yaml, "url", Value(context, urlText, "url", propertyName: null));
        }

        Map(yaml, context, entry["headers"], "headers");

        if (entry["disabled"] is JsonValue disabled && disabled.TryGetValue<bool>(out var isDisabled) && isDisabled)
        {
            yaml.Append("    disabled: true\n");
        }
    }

    private static void Map(StringBuilder yaml, EntryContext context, JsonNode? node, string field)
    {
        if (node is not JsonObject map || map.Count == 0)
        {
            return;
        }

        yaml.Append("    ").Append(field).Append(":\n");
        foreach (var (key, value) in map)
        {
            yaml.Append("      ").Append(Quote(key)).Append(": ");
            yaml.Append(value is null ? "null" : Quote(Value(context, Text(value)!, $"{field}.{key}", key)));
            yaml.Append('\n');
        }
    }

    /// <summary>
    /// One value for the servers file: client variables translated, and a
    /// secret lifted out into a variable reference.
    /// </summary>
    private static string Value(EntryContext context, string value, string field, string? propertyName)
    {
        foreach (var (variable, replacement) in context.Substitutions)
        {
            value = value.Replace(variable, replacement, StringComparison.Ordinal);
        }

        // VS Code's prompted inputs become plain variables the user sets.
        var input = value.IndexOf("${input:", StringComparison.Ordinal);
        while (input >= 0)
        {
            var close = value.IndexOf('}', input);
            if (close < 0)
            {
                break;
            }

            var id = value[(input + "${input:".Length)..close];
            var variable = VariableName(id);
            context.Notes.Add(
                $"Server '{context.Name}': '{field}' used the VS Code input '{id}'; it now reads ${{{variable}}}. " +
                $"Set {variable} before starting the proxy.");
            value = string.Concat(value.AsSpan(0, input), $"${{{variable}}}", value.AsSpan(close + 1));
            input = value.IndexOf("${input:", StringComparison.Ordinal);
        }

        // A value that already references a variable is not a secret written in
        // the file, and lifting it would hide the reference the user chose.
        if (value.Contains("${", StringComparison.Ordinal) ||
            (!IsSensitiveKey(propertyName) && SecretScanner.Scan(value, propertyName, includePii: false).IsClean))
        {
            return value.Replace("$", "$$", StringComparison.Ordinal)
                .Replace("$${", "${", StringComparison.Ordinal);
        }

        var label = $"{context.Name}_{propertyName ?? field}";
        var name = VariableName(label);
        for (var suffix = 2; !context.UsedVariables.Add(name); suffix++)
        {
            name = VariableName($"{label}_{suffix}");
        }

        context.Secrets.Add(new LiftedSecret(name, value, context.Name, field));
        return $"${{{name}}}";
    }

    private static readonly HashSet<string> _sensitiveKeyParts = new(
        ["TOKEN", "SECRET", "PASSWORD", "PASSWD", "PASS", "KEY", "APIKEY", "AUTH", "AUTHORIZATION",
         "CREDENTIAL", "CREDENTIALS", "PAT", "COOKIE", "PRIVATE"],
        StringComparer.Ordinal);

    /// <summary>
    /// Whether an env or header name says its value is a credential, whatever
    /// the value looks like: <c>GITHUB_TOKEN</c>, <c>X-Api-Key</c>, <c>DB_PASSWORD</c>.
    /// </summary>
    /// <remarks>
    /// Broader than the secret scanner's own field list on purpose. The scanner
    /// runs on tool traffic, where a false positive breaks a call; here a false
    /// positive only moves a harmless value into an environment variable, and a
    /// false negative commits a password to a file meant for review.
    /// </remarks>
    internal static bool IsSensitiveKey(string? key) =>
        key is not null &&
        VariableName(key).Split('_', StringSplitOptions.RemoveEmptyEntries).Any(_sensitiveKeyParts.Contains);

    /// <summary>An environment variable name: upper case, with every other character turned into '_'.</summary>
    internal static string VariableName(string text)
    {
        var builder = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            builder.Append(char.IsAsciiLetterOrDigit(c) ? char.ToUpperInvariant(c) : '_');
        }

        if (builder.Length == 0 || char.IsAsciiDigit(builder[0]))
        {
            builder.Insert(0, '_');
        }

        return builder.ToString();
    }

    /// <summary>A value as text: a string as itself, anything else as its JSON.</summary>
    private static string? Text(JsonNode? node) => node switch
    {
        null => null,
        JsonValue value when value.TryGetValue<string>(out var text) => text,
        _ => node.ToJsonString(),
    };

    private static void Field(StringBuilder yaml, string key, string value) =>
        yaml.Append("    ").Append(key).Append(": ").Append(Quote(value)).Append('\n');

    /// <summary>
    /// A YAML double-quoted scalar. Every value is quoted, so nothing the user
    /// wrote is ever re-typed: <c>"true"</c>, <c>"8080"</c> and <c>"no"</c> stay
    /// strings, which is what the client meant too.
    /// </summary>
    internal static string Quote(string value)
    {
        var builder = new StringBuilder(value.Length + 2).Append('"');
        foreach (var c in value)
        {
            switch (c)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                case < ' ' or '\u007f':
                    builder.Append("\\u").Append(((int)c).ToString("x4", System.Globalization.CultureInfo.InvariantCulture));
                    break;
                default:
                    builder.Append(c);
                    break;
            }
        }

        return builder.Append('"').ToString();
    }

    /// <summary>Indented JSON, as clients write their own configs, with a trailing newline.</summary>
    internal static string WriteJson(JsonNode node)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(
                   stream,
                   new JsonWriterOptions
                   {
                       Indented = true,
                       // Paths and URLs stay readable: "+" and "&" are not
                       // escaped. Safe because this is a file, never HTML.
                       Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                   }))
        {
            node.WriteTo(writer);
        }

        return Encoding.UTF8.GetString(stream.ToArray()) + "\n";
    }
}
