using System.IO.Compression;
using System.Text;
using System.Text.Json;
using McpGuardrails.Core.Serialization;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Pins;

/// <summary>
/// The pins file could not be read, parsed, written or changed as asked.
/// </summary>
/// <remarks>
/// Always fatal where it is thrown at startup. A pins file that exists but cannot
/// be understood must not be treated as "nothing pinned": that would trust
/// whatever every server is serving right now, which is the one thing a pin
/// exists to refuse.
/// </remarks>
public sealed class PinsException(string message, Exception? innerException = null)
    : Exception(message, innerException);

/// <summary>Reads and writes the pins file.</summary>
public static class PinsFile
{
    /// <summary>The environment variable naming the pins file.</summary>
    public const string PathVariable = "GUARDRAILS_PINS";

    /// <summary>The file name used under the proxy's home directory.</summary>
    public const string DefaultFileName = "pins.json";

    /// <summary>
    /// Where the pins file is: the environment variable, else the policy's
    /// <c>scanners.pins.file</c>, else <c>~/.mcp-guardrails/pins.json</c>.
    /// </summary>
    /// <param name="settings">The policy's pin settings.</param>
    /// <param name="policyPath">The policy file, against whose directory a relative path resolves.</param>
    /// <param name="getVariable">Reads the environment.</param>
    /// <param name="homeDirectory">The user's home directory.</param>
    /// <remarks>
    /// A relative path resolves against the policy file rather than the working
    /// directory, because a proxy launched by a desktop client has no working
    /// directory anyone chose; the policy file is the one place the operator did.
    /// </remarks>
    public static string ResolvePath(
        PinSettings settings,
        string policyPath,
        Func<string, string?> getVariable,
        string homeDirectory)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(policyPath);
        ArgumentNullException.ThrowIfNull(getVariable);
        ArgumentNullException.ThrowIfNull(homeDirectory);

        if (getVariable(PathVariable) is { Length: > 0 } fromEnvironment)
        {
            return fromEnvironment;
        }

        if (settings.File is not { } configured)
        {
            return Path.Combine(homeDirectory, ".mcp-guardrails", DefaultFileName);
        }

        if (configured.StartsWith("~/", StringComparison.Ordinal))
        {
            return Path.Combine(homeDirectory, configured[2..]);
        }

        return Path.IsPathRooted(configured)
            ? configured
            : Path.GetFullPath(configured, Path.GetDirectoryName(Path.GetFullPath(policyPath))!);
    }

    /// <summary>Loads the pins file, or null when there is none yet.</summary>
    /// <exception cref="PinsException">The file exists but cannot be read or understood.</exception>
    public static PinsDocument? Load(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new PinsException($"Could not read the pins file '{path}': {ex.Message}", ex);
        }

        return Parse(text, path);
    }

    /// <summary>Parses and checks a pins file's text.</summary>
    /// <param name="text">The file's contents.</param>
    /// <param name="path">Where it came from, for the error message.</param>
    /// <exception cref="PinsException">The text is not a pins file this build understands.</exception>
    public static PinsDocument Parse(string text, string path)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(path);

        PinsDocument? document;
        try
        {
            document = JsonSerializer.Deserialize(text, PinsJsonContext.Default.PinsDocument);
        }
        catch (JsonException ex)
        {
            throw Invalid(path, ex.Message, ex);
        }

        if (document is null)
        {
            throw Invalid(path, "it is empty (null).");
        }

        if (document.Version != PinsDocument.CurrentVersion)
        {
            throw Invalid(
                path,
                document.Version is null
                    ? "'version' is missing."
                    : $"version {document.Version} is not supported; this build reads version {PinsDocument.CurrentVersion}.");
        }

        foreach (var (name, server) in document.EffectiveServers)
        {
            if (!UpstreamServerConfig.IsValidName(name))
            {
                throw Invalid(path, $"'{name}' is not a valid server name.");
            }

            if (server is null || !CanonicalJson.IsHash(server.Identity))
            {
                throw Invalid(path, $"server '{name}' has no valid 'identity' hash.");
            }

            foreach (var (tool, pin) in server.EffectiveTools)
            {
                if (pin is null || !CanonicalJson.IsHash(pin.Hash))
                {
                    throw Invalid(path, $"tool '{tool}' of server '{name}' has no valid 'hash'.");
                }
            }
        }

        return Normalized(document);
    }

    /// <summary>The file's text: indented, keys sorted, ending in a newline.</summary>
    public static string Serialize(PinsDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);

        return JsonSerializer.Serialize(Normalized(document), PinsJsonContext.Default.PinsDocument)
                   .ReplaceLineEndings("\n") + "\n";
    }

    /// <summary>
    /// Writes the pins file so that a crash leaves either the old file or the new
    /// one, never half of each.
    /// </summary>
    /// <exception cref="PinsException">The file or its directory could not be written.</exception>
    public static void Save(string path, PinsDocument document)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(document);

        var full = Path.GetFullPath(path);
        var temporary = $"{full}.{Guid.NewGuid():N}.tmp";

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);

            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write))
            {
                stream.Write(Encoding.UTF8.GetBytes(Serialize(document)));
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, full, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Only there when the write got as far as the rename.
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }

            throw new PinsException($"Could not write the pins file '{path}': {ex.Message}", ex);
        }
    }

    /// <summary>Compresses a canonical definition for <see cref="PinnedTool.Definition"/>.</summary>
    public static string Compress(string canonical)
    {
        ArgumentNullException.ThrowIfNull(canonical);

        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionLevel.SmallestSize))
        {
            deflate.Write(Encoding.UTF8.GetBytes(canonical));
        }

        return Convert.ToBase64String(output.ToArray());
    }

    /// <summary>Reverses <see cref="Compress"/>.</summary>
    /// <exception cref="PinsException">The value is not something <see cref="Compress"/> produced.</exception>
    public static string Decompress(string compressed)
    {
        ArgumentNullException.ThrowIfNull(compressed);

        try
        {
            using var input = new MemoryStream(Convert.FromBase64String(compressed));
            using var deflate = new DeflateStream(input, CompressionMode.Decompress);
            using var reader = new StreamReader(deflate, Encoding.UTF8);
            return reader.ReadToEnd();
        }
        catch (Exception ex) when (ex is FormatException or InvalidDataException)
        {
            throw new PinsException($"The stored definition is corrupt: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// The same document with every map ordered by ordinal comparison.
    /// </summary>
    /// <remarks>
    /// The deserializer builds its sorted maps with the default, culture-aware
    /// comparer. Rebuilt here so the order a team sees in a diff, and which keys
    /// count as equal, never depends on the machine's culture.
    /// </remarks>
    private static PinsDocument Normalized(PinsDocument document) => document with
    {
        Servers = new SortedDictionary<string, PinnedServer>(
            document.EffectiveServers.ToDictionary(
                server => server.Key,
                server => server.Value with
                {
                    Tools = new SortedDictionary<string, PinnedTool>(
                        server.Value.EffectiveTools.ToDictionary(t => t.Key, t => t.Value, StringComparer.Ordinal),
                        StringComparer.Ordinal),
                },
                StringComparer.Ordinal),
            StringComparer.Ordinal),
    };

    private static PinsException Invalid(string path, string problem, Exception? inner = null) =>
        new($"The pins file '{path}' is not valid: {problem} Fix or delete it; a pins file that cannot be read " +
            "is never replaced automatically, because that would trust whatever the servers serve now.", inner);
}
