using System.Text.Json.Serialization;
using McpGuardrails.Core.Pins;
using McpGuardrails.Core.Upstream;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Scanners;

/// <summary>The report <c>scan</c> prints: every scanned server, tool and finding.</summary>
/// <remarks>
/// Also the <c>--json</c> format, so its shape is a contract: field names are
/// spelt out with <see cref="JsonPropertyNameAttribute"/>, and <c>version</c>
/// changes if a field changes meaning.
///
/// Names, hashes and detector names only - never a description, schema text or
/// a suggested value. Those are written by the server being scanned, and a report
/// that quotes them is a report that can carry an injection into whatever reads
/// it next (a CI log an agent summarizes, a dashboard). The hash is how to tell
/// two definitions apart without the text.
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

    /// <summary>Tools scanned, across every server.</summary>
    [JsonPropertyName("tool_count")]
    public int ToolCount => Servers.Sum(server => server.Tools.Count);

    /// <summary>Findings, across every tool.</summary>
    [JsonPropertyName("finding_count")]
    public int FindingCount => Servers.Sum(server => server.Tools.Sum(tool => tool.Findings.Count));

    /// <summary>
    /// True when every configured server was scanned and nothing was found: the
    /// condition for exit code 0.
    /// </summary>
    /// <remarks>
    /// A server that could not be reached is not clean, only unknown, and a CI
    /// job that passes because the thing it was meant to check was down is the
    /// fail-open this project exists to avoid.
    /// </remarks>
    [JsonPropertyName("clean")]
    public bool IsClean => FindingCount == 0 && Unavailable.Count == 0;

    /// <summary>Scans every tool of every connected server.</summary>
    /// <param name="servers">Each server's name, how it was reached, and the definitions it advertised.</param>
    /// <param name="unavailable">Servers that were configured but could not be reached.</param>
    public static ScanReport Build(
        IEnumerable<(UpstreamServerConfig? Config, string Name, IReadOnlyList<Tool> Tools)> servers,
        IEnumerable<UnscannedServer> unavailable)
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
        };
    }
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

/// <summary>One scanned tool definition.</summary>
public sealed record ToolScan
{
    /// <summary>The tool's name as its server knows it, unqualified.</summary>
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    /// <summary>
    /// The hash pinning records for this definition: the same canonical form, so
    /// a scan and a pins file can be compared, and repeated scans show which
    /// definitions changed between releases.
    /// </summary>
    [JsonPropertyName("hash")]
    public required string Hash { get; init; }

    /// <summary>
    /// Which behaviour hints the tool declares, e.g. <c>readOnlyHint</c>. Empty
    /// when it declares none - the case a policy that matches on annotations
    /// cannot see into.
    /// </summary>
    [JsonPropertyName("annotations")]
    public required IReadOnlyList<string> Annotations { get; init; }

    [JsonPropertyName("findings")]
    public required IReadOnlyList<ScanFinding> Findings { get; init; }

    /// <summary>Runs every check over one definition.</summary>
    public static ToolScan Of(Tool tool)
    {
        ArgumentNullException.ThrowIfNull(tool);

        var findings = new List<ScanFinding>();

        // The metadata heuristics the proxy applies at startup, unchanged, so a
        // tool scan flags is a tool the proxy would annotate or withhold.
        var (report, fields) = ToolMetadataGate.Scan(tool);
        if (!report.IsClean)
        {
            findings.Add(new ScanFinding
            {
                Check = ScanFinding.Injection,
                Names = report.Heuristics,
                Where = fields,
            });
        }

        foreach (var hit in SchemaExampleScanner.Scan(tool.Name, tool.InputSchema))
        {
            findings.Add(new ScanFinding
            {
                Check = ScanFinding.SchemaSuggestion,
                Names = [hit.Detector],
                Where = [$"input schema {hit.Location}"],
            });
        }

        foreach (var mismatch in AnnotationCheck.Check(tool))
        {
            findings.Add(new ScanFinding
            {
                Check = ScanFinding.ReadOnlyMismatch,
                Names = [mismatch.Verb],
                Where = [mismatch.Field],
            });
        }

        return new ToolScan
        {
            Name = tool.Name,
            Hash = ToolDefinition.Hash(tool),
            Annotations = DeclaredHints(tool.Annotations),
            Findings = findings,
        };
    }

    private static List<string> DeclaredHints(ToolAnnotations? annotations)
    {
        var hints = new List<string>();
        if (annotations is null)
        {
            return hints;
        }

        Add(annotations.ReadOnlyHint, "readOnlyHint");
        Add(annotations.DestructiveHint, "destructiveHint");
        Add(annotations.IdempotentHint, "idempotentHint");
        Add(annotations.OpenWorldHint, "openWorldHint");
        return hints;

        void Add(bool? value, string name)
        {
            if (value is { } set)
            {
                hints.Add($"{name}={(set ? "true" : "false")}");
            }
        }
    }
}

/// <summary>One thing a check found in a tool definition.</summary>
public sealed record ScanFinding
{
    /// <summary>The injection heuristics matched text the model reads.</summary>
    public const string Injection = "injection";

    /// <summary>An argument detector fired on a value the input schema suggests.</summary>
    public const string SchemaSuggestion = "schema-suggestion";

    /// <summary>The tool declares <c>readOnlyHint: true</c> but is named or described like a write.</summary>
    public const string ReadOnlyMismatch = "read-only-mismatch";

    /// <summary>Which check: one of the constants above.</summary>
    [JsonPropertyName("check")]
    public required string Check { get; init; }

    /// <summary>
    /// What fired: heuristic names, a detector name, or the verb that suggested a
    /// write. Always from the proxy's own vocabulary.
    /// </summary>
    [JsonPropertyName("names")]
    public required IReadOnlyList<string> Names { get; init; }

    /// <summary>Which parts of the definition it fired in.</summary>
    [JsonPropertyName("where")]
    public required IReadOnlyList<string> Where { get; init; }

    /// <summary>One line for the human-readable report.</summary>
    public string Describe() => Check switch
    {
        Injection => $"prompt-injection heuristics ({string.Join(", ", Names)}) in its {string.Join(", ", Where)}",
        SchemaSuggestion => $"{ArgumentDetector.Describe(Names[0])} suggested by its {Where[0]}",
        _ => $"declares readOnlyHint: true, but its {Where[0]} says '{Names[0]}'",
    };
}

/// <summary>A configured server that was not scanned, and why.</summary>
public sealed record UnscannedServer
{
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("reason")]
    public required string Reason { get; init; }
}
