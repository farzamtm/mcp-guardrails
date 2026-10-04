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
    public void ServerChosenTextInAFindingsLocation_IsNeutralized()
    {
        var finding = new ScanFinding
        {
            Check = ScanFinding.SchemaSuggestion,
            Names = ["ssrf"],
            Where = ["input schema properties.\u001b]52;c;eA==\u0007"],
        };

        var text = ScanReportText.Render(Report(
            [new ServerScan { Name = "fs", Transport = "stdio", Tools = [Tool("fetch", finding)] }]));

        Assert.DoesNotContain('\u001b', text);
        Assert.DoesNotContain('\u0007', text);
    }

    [Fact]
    public void AdvisoryFindings_AreMarked_AndDoNotFailTheReport()
    {
        var advisory = _mismatch with { Where = ["description"], Advisory = true };

        var text = ScanReportText.Render(Report(
            [new ServerScan { Name = "fs", Transport = "stdio", Tools = [Tool("read_file", advisory)] }]));

        Assert.Equal(
            string.Join(
                Environment.NewLine,
                "fs  stdio",
                "  ? read_file: declares readOnlyHint: true, but its description says 'delete' (advisory)",
                "  1 tool, 0 findings, 1 advisory, 1 declaring no annotations",
                "Clean: 1 tool scanned, nothing found; 1 advisory note.",
                string.Empty),
            text);
    }

    [Fact]
    public void AdvisoryNotes_AreCountedBesideRealFindings()
    {
        var advisory = _mismatch with { Advisory = true };

        var text = ScanReportText.Render(Report(
            [new ServerScan { Name = "fs", Transport = "stdio", Tools = [Tool("a", _mismatch, advisory), Tool("b", advisory)] }]));

        Assert.EndsWith($"1 finding in 1 tool; 2 advisory notes.{Environment.NewLine}", text, StringComparison.Ordinal);
    }

    [Fact]
    public void AReportOfNoServer_IsNotClean_AndListsWhatWasDisabled()
    {
        var text = ScanReportText.Render(new ScanReport { Servers = [], Disabled = ["legacy"] });

        Assert.Equal(
            string.Join(
                Environment.NewLine,
                "legacy  disabled, not scanned",
                "Nothing was scanned: no server is enabled.",
                string.Empty),
            text);
    }
}
