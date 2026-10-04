using System.Text;
using McpGuardrails.Core.Text;

namespace McpGuardrails.Core.Scanners;

/// <summary>The human-readable form of a <see cref="ScanReport"/>.</summary>
/// <remarks>
/// Every string a server could have influenced goes through
/// <see cref="TerminalText.Printable"/> on its way out, including the finding
/// descriptions, whose locations are built from schema keys the server chose:
/// the report is printed to the terminal of someone deciding whether to trust
/// that server, and must not be something the server can rewrite.
/// </remarks>
public static class ScanReportText
{
    /// <summary>Renders the report, one line per finding, ending with the verdict.</summary>
    public static string Render(ScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var text = new StringBuilder();

        foreach (var server in report.Servers)
        {
            text.Append(TerminalText.Printable(server.Name)).Append("  ").Append(server.Transport);
            if (server.Source is { } source)
            {
                text.Append("  ").Append(TerminalText.Printable(source));
            }

            text.AppendLine();

            foreach (var tool in server.Tools)
            {
                foreach (var finding in tool.Findings)
                {
                    text.Append(finding.Advisory ? "  ? " : "  ! ")
                        .Append(TerminalText.Printable(tool.Name)).Append(": ")
                        .Append(TerminalText.Printable(finding.Describe()))
                        .AppendLine(finding.Advisory ? " (advisory)" : string.Empty);
                }
            }

            var findings = server.Tools.Sum(tool => tool.Findings.Count(f => !f.Advisory));
            var advisories = server.Tools.Sum(tool => tool.Findings.Count(f => f.Advisory));
            var unannotated = server.Tools.Count(tool => tool.Annotations.Count == 0);
            text.Append("  ").Append(Count(server.Tools.Count, "tool")).Append(", ")
                .Append(Count(findings, "finding"));
            if (advisories > 0)
            {
                text.Append(", ").Append(advisories).Append(" advisory");
            }

            if (unannotated > 0)
            {
                text.Append(", ").Append(unannotated).Append(" declaring no annotations");
            }

            text.AppendLine();
        }

        foreach (var missing in report.Unavailable)
        {
            text.Append(TerminalText.Printable(missing.Name)).Append("  unavailable, not scanned: ")
                .AppendLine(TerminalText.Printable(missing.Reason));
        }

        foreach (var name in report.Disabled)
        {
            text.Append(TerminalText.Printable(name)).AppendLine("  disabled, not scanned");
        }

        text.Append(Verdict(report)).AppendLine();
        return text.ToString();
    }

    private static string Verdict(ScanReport report)
    {
        var advisory = report.AdvisoryCount > 0 ? $"; {Count(report.AdvisoryCount, "advisory note")}" : string.Empty;

        if (report.IsClean)
        {
            return $"Clean: {Count(report.ToolCount, "tool")} scanned, nothing found{advisory}.";
        }

        if (report.Servers.Count == 0 && report.Unavailable.Count == 0)
        {
            return "Nothing was scanned: no server is enabled.";
        }

        var flagged = report.Servers.Sum(server => server.Tools.Count(tool => tool.Findings.Any(f => !f.Advisory)));
        var unscanned = report.Unavailable.Count > 0 ? $"; {Count(report.Unavailable.Count, "server")} not scanned" : string.Empty;
        return $"{Count(report.FindingCount, "finding")} in {Count(flagged, "tool")}{unscanned}{advisory}.";
    }

    private static string Count(int count, string noun) => count == 1 ? $"1 {noun}" : $"{count} {noun}s";
}
