using System.Diagnostics;
using System.Text.Json.Serialization;
using McpGuardrails.Core.Pins;
using McpGuardrails.Core.Text;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Scanners;

/// <summary>One scanned tool definition.</summary>
public sealed record ToolScan
{
    /// <summary>
    /// The tool's name as its server knows it, unqualified, with control
    /// characters replaced.
    /// </summary>
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
                Advisory = mismatch.Advisory,
            });
        }

        return new ToolScan
        {
            // Hashed as served, reported as printable: the hash must match the
            // pins file, the name must not drive the terminal it is shown in.
            Name = TerminalText.Printable(tool.Name),
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

    /// <summary>
    /// True for a finding worth a look that does not fail the scan: a verb in a
    /// description, which is as likely to be "never deletes anything" as a lie.
    /// </summary>
    [JsonPropertyName("advisory")]
    public bool Advisory { get; init; }

    /// <summary>One line for the human-readable report.</summary>
    public string Describe() => Check switch
    {
        Injection => $"prompt-injection heuristics ({string.Join(", ", Names)}) in its {string.Join(", ", Where)}",
        SchemaSuggestion => $"{ArgumentDetector.Describe(Names[0])} suggested by its {Where[0]}",
        ReadOnlyMismatch => $"declares readOnlyHint: true, but its {Where[0]} says '{Names[0]}'",
        _ => throw new UnreachableException($"No description for the scan check '{Check}'."),
    };
}
