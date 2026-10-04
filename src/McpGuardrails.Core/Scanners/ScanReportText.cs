using System.Text;

namespace McpGuardrails.Core.Scanners;

/// <summary>The human-readable form of a <see cref="ScanReport"/>.</summary>
public static class ScanReportText
{
    /// <summary>Renders the report, one line per finding, ending with the verdict.</summary>
    public static string Render(ScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var text = new StringBuilder();

        foreach (var server in report.Servers)
        {
            text.Append(Printable(server.Name)).Append("  ").Append(server.Transport);
            if (server.Source is { } source)
            {
                text.Append("  ").Append(Printable(source));
            }

            text.AppendLine();

            foreach (var tool in server.Tools)
            {
                foreach (var finding in tool.Findings)
                {
                    text.Append("  ! ").Append(Printable(tool.Name)).Append(": ").AppendLine(finding.Describe());
                }
            }

            var findings = server.Tools.Sum(tool => tool.Findings.Count);
            var unannotated = server.Tools.Count(tool => tool.Annotations.Count == 0);
            text.Append("  ").Append(Count(server.Tools.Count, "tool")).Append(", ")
                .Append(Count(findings, "finding"));
            if (unannotated > 0)
            {
                text.Append(", ").Append(unannotated).Append(" declaring no annotations");
            }

            text.AppendLine();
        }

        foreach (var missing in report.Unavailable)
        {
            text.Append(Printable(missing.Name)).Append("  unavailable, not scanned: ").AppendLine(Printable(missing.Reason));
        }

        var flagged = report.Servers.Sum(server => server.Tools.Count(tool => tool.Findings.Count > 0));
        text.Append(report.IsClean
            ? $"Clean: {Count(report.ToolCount, "tool")} scanned, nothing found."
            : $"{Count(report.FindingCount, "finding")} in {Count(flagged, "tool")}" +
              (report.Unavailable.Count > 0 ? $"; {Count(report.Unavailable.Count, "server")} not scanned." : "."));
        text.AppendLine();

        return text.ToString();
    }

    /// <summary>
    /// Replaces control characters, so a tool name a server chose cannot move the
    /// cursor, clear the screen or forge a line of the report in a terminal.
    /// </summary>
    internal static string Printable(string value)
    {
        if (!value.Any(char.IsControl))
        {
            return value;
        }

        return string.Create(value.Length, value, static (span, source) =>
        {
            for (var i = 0; i < source.Length; i++)
            {
                span[i] = char.IsControl(source[i]) ? '?' : source[i];
            }
        });
    }

    private static string Count(int count, string noun) => count == 1 ? $"1 {noun}" : $"{count} {noun}s";
}
