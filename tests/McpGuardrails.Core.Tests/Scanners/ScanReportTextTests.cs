using McpGuardrails.Core.Scanners;

namespace McpGuardrails.Core.Tests.Scanners;

/// <summary>Tests for the human-readable scan report.</summary>
public sealed class ScanReportTextTests
{
    private static ToolScan Tool(string name, params ScanFinding[] findings) => new()
    {
        Name = name,
        Hash = "sha256:00",
        Annotations = findings.Length == 0 ? ["readOnlyHint=true"] : [],
        Findings = findings,
    };

    private static readonly ScanFinding _mismatch = new()
    {
        Check = ScanFinding.ReadOnlyMismatch,
        Names = ["delete"],
        Where = ["name"],
    };

    private static ScanReport Report(IReadOnlyList<ServerScan> servers, params UnscannedServer[] unavailable) =>
        new() { Servers = servers, Unavailable = unavailable };

    [Fact]
    public void Null_IsRejected() =>
        Assert.Throws<ArgumentNullException>(() => ScanReportText.Render(null!));

    [Fact]
    public void ACleanReport_SaysSo()
    {
        var text = ScanReportText.Render(Report(
            [new ServerScan { Name = "fs", Transport = "stdio", Source = "npx -y pkg@1.0.0", Tools = [Tool("read_file")] }]));

        Assert.Equal(
            string.Join(
                Environment.NewLine,
                "fs  stdio  npx -y pkg@1.0.0",
                "  1 tool, 0 findings",
                "Clean: 1 tool scanned, nothing found.",
                string.Empty),
            text);
    }

    [Fact]
    public void Findings_AreListedPerTool_WithTheTotals()
    {
        var text = ScanReportText.Render(Report(
            [
                new ServerScan
                {
                    Name = "db",
                    Transport = "http",
                    Tools = [Tool("delete_row", _mismatch, _mismatch), Tool("drop_table", _mismatch)],
                },
            ]));

        Assert.Equal(
            string.Join(
                Environment.NewLine,
                "db  http",
                "  ! delete_row: declares readOnlyHint: true, but its name says 'delete'",
                "  ! delete_row: declares readOnlyHint: true, but its name says 'delete'",
                "  ! drop_table: declares readOnlyHint: true, but its name says 'delete'",
                "  2 tools, 3 findings, 2 declaring no annotations",
                "3 findings in 2 tools.",
                string.Empty),
            text);
    }

    [Fact]
    public void UnscannedServers_AreListed_AndMakeTheReportUnclean()
    {
        var text = ScanReportText.Render(Report(
            [new ServerScan { Name = "fs", Transport = "stdio", Tools = [] }],
            new UnscannedServer { Name = "docs", Reason = "connection refused" }));

        Assert.Contains("docs  unavailable, not scanned: connection refused", text, StringComparison.Ordinal);
        Assert.EndsWith($"0 findings in 0 tools; 1 server not scanned.{Environment.NewLine}", text, StringComparison.Ordinal);
    }

    [Fact]
    public void ControlCharactersInServerChosenText_AreNeutralized()
    {
        var text = ScanReportText.Render(Report(
            [new ServerScan { Name = "fs", Transport = "stdio", Tools = [Tool("evil\u001b[2J\rtool", _mismatch)] }]));

        Assert.Contains("  ! evil?[2J?tool:", text, StringComparison.Ordinal);
        Assert.DoesNotContain('\u001b', text);
    }

    [Fact]
    public void Printable_LeavesOrdinaryTextAlone()
    {
        const string Name = "read_file";
        Assert.Same(Name, ScanReportText.Printable(Name));
    }
}
