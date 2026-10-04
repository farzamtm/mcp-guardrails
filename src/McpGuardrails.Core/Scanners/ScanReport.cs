using System.Text.Json;
using System.Text.Json.Serialization;
using McpGuardrails.Core.Pins;
using McpGuardrails.Core.Serialization;
using McpGuardrails.Core.Upstream;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Scanners;

/// <summary>The report <c>scan</c> prints: every scanned server, tool and finding.</summary>
/// <remarks>
/// Also the <c>--json</c> format, so its shape is a contract: field names are
/// spelt out with <see cref="JsonPropertyNameAttribute"/>. Fields may be added
/// without changing <c>version</c>, so a reader should ignore fields it does not
/// know; removing a field or changing what one means bumps it.
///
/// Names, hashes and detector names only - never a description, schema text or
/// a suggested value. Those are written by the server being scanned, and a report
/// that quotes them is a report that can carry an injection into whatever reads
/// it next (a CI log an agent summarizes, a dashboard). The hash is how to tell
/// two definitions apart without the text. The few server-chosen strings that are
/// reported - tool names, schema keys in a location - have their control
/// characters replaced before they get here.
/// </remarks>
public sealed record ScanReport
{
    /// <summary>The report format's version.</summary>
    public const int CurrentVersion = 1;

    [JsonPropertyName("version")]
    public int Version { get; init; } = CurrentVersion;

    [JsonPropertyName("servers")]
    public required IReadOnlyList<ServerScan> Servers { get; init; }

    /// <summary>Optional servers that could not be reached, so were not scanned.</summary>
    [JsonPropertyName("unavailable")]
    public IReadOnlyList<UnscannedServer> Unavailable { get; init; } = [];

    /// <summary>Servers the servers file marks <c>disabled</c>, so were not scanned.</summary>
    /// <remarks>
    /// Listed so a report says what it did not look at: a file whose every
    /// server is disabled otherwise produces a report about nothing.
    /// </remarks>
    [JsonPropertyName("disabled")]
    public IReadOnlyList<string> Disabled { get; init; } = [];

    /// <summary>Tools scanned, across every server.</summary>
    [JsonPropertyName("tool_count")]
    public int ToolCount => Servers.Sum(server => server.Tools.Count);

    /// <summary>Findings that fail the scan, across every tool. Advisory ones are not counted.</summary>
    [JsonPropertyName("finding_count")]
    public int FindingCount => Servers.Sum(server => server.Tools.Sum(tool => tool.Findings.Count(f => !f.Advisory)));

    /// <summary>Advisory findings, across every tool: worth a look, but they do not fail the scan.</summary>
    [JsonPropertyName("advisory_count")]
    public int AdvisoryCount => Servers.Sum(server => server.Tools.Sum(tool => tool.Findings.Count(f => f.Advisory)));

    /// <summary>
    /// True when at least one server was scanned, every configured server was
    /// scanned, and nothing that fails the scan was found: the condition for exit
    /// code 0.
    /// </summary>
    /// <remarks>
    /// A server that could not be reached is not clean, only unknown, and a scan
    /// of no server at all has checked nothing. A CI job that passes because the
    /// thing it was meant to check was down - or was never there - is the
    /// fail-open this project exists to avoid.
    /// </remarks>
    [JsonPropertyName("clean")]
    public bool IsClean => Servers.Count > 0 && FindingCount == 0 && Unavailable.Count == 0;

    /// <summary>Scans every tool of every connected server.</summary>
    /// <param name="servers">Each server's name, how it was reached, and the definitions it advertised.</param>
    /// <param name="unavailable">Servers that were configured but could not be reached.</param>
    /// <param name="disabled">Servers the configuration lists as disabled.</param>
    public static ScanReport Build(
        IEnumerable<(UpstreamServerConfig? Config, string Name, IReadOnlyList<Tool> Tools)> servers,
        IEnumerable<UnscannedServer> unavailable,
        IEnumerable<string>? disabled = null)
    {
        ArgumentNullException.ThrowIfNull(servers);
        ArgumentNullException.ThrowIfNull(unavailable);

        return new ScanReport
        {
            Servers =
            [
                .. servers.Select(server => new ServerScan
                {
                    Name = server.Name,
                    Transport = (server.Config?.Transport ?? UpstreamTransport.Stdio).ToWireName(),
                    Source = server.Config is null ? null : ServerIdentity.Hint(server.Config),
                    Identity = server.Config is null ? null : ServerIdentity.Fingerprint(server.Config),
                    Tools = [.. server.Tools.Select(ToolScan.Of)],
                }),
            ],
            Unavailable = [.. unavailable],
            Disabled = [.. disabled ?? []],
        };
    }

    /// <summary>The <c>--json</c> form, indented, ending with a newline.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, ScanJsonContext.Default.ScanReport) + Environment.NewLine;
}

/// <summary>One scanned server.</summary>
public sealed record ServerScan
{
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    /// <summary><c>stdio</c>, <c>http</c> or <c>sse</c>.</summary>
    [JsonPropertyName("transport")]
    public required string Transport { get; init; }

    /// <summary>
    /// How the server was started or reached, as written before variable
    /// expansion, so a <c>${TOKEN}</c> reference is shown but never its value.
    /// </summary>
    [JsonPropertyName("source")]
    public string? Source { get; init; }

    /// <summary>The fingerprint pinning would key this server on.</summary>
    [JsonPropertyName("identity")]
    public string? Identity { get; init; }

    [JsonPropertyName("tools")]
    public required IReadOnlyList<ToolScan> Tools { get; init; }
}

/// <summary>A configured server that was not scanned, and why.</summary>
public sealed record UnscannedServer
{
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    /// <summary>
    /// Why, as the connection reported it. It can carry text the server sent
    /// (an error message), so the text report prints it through
    /// <see cref="Text.TerminalText"/>, and the JSON form escapes it.
    /// </summary>
    [JsonPropertyName("reason")]
    public required string Reason { get; init; }
}
