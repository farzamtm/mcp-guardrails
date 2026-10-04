using McpGuardrails.Core.Audit;
using McpGuardrails.Core.Pins;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Text;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Cli.Commands;

/// <summary>
/// <c>pins status|diff|accept|reset</c>: looking at and accepting changes to
/// pinned tool definitions.
/// </summary>
/// <remarks>
/// The proxy never re-pins a server it has seen before; these commands are the
/// only way a pin changes after first use, so every change to the pins file is a
/// person's explicit decision and leaves a line in the audit log.
///
/// status, diff and accept connect to the servers, because the current
/// definitions only exist in the servers themselves. reset does not: forgetting a
/// server needs nothing from it. Output goes to stdout - this command is not an
/// MCP server, so stdout is not the JSON-RPC wire here.
/// </remarks>
internal sealed class PinsCommand : ICliCommand
{
    private const string _usage =
        "Usage: pins status | pins diff <server> [<tool>] | pins accept <server> [<tool>...] | " +
        "pins accept --all | pins reset <server>";

    public async Task<int> RunAsync(string[] args)
    {
        var operands = CliArgs.Operands(args, "pins", "--servers", "--path");
        if (operands.Count == 0)
        {
            throw new CommandFailedException(2, _usage);
        }

        return operands[0] switch
        {
            "status" when operands.Count == 1 => await StatusAsync(args),
            "diff" when operands.Count is 2 or 3 => await DiffAsync(args, operands[1], operands.ElementAtOrDefault(2)),
            "accept" when CliArgs.Has(args, "--all") && operands.Count == 1 => await AcceptAsync(args, null, []),
            "accept" when !CliArgs.Has(args, "--all") && operands.Count >= 2 =>
                await AcceptAsync(args, operands[1], operands.Skip(2).ToList()),
            "reset" when operands.Count == 2 => await ResetAsync(operands[1]),
            _ => throw new CommandFailedException(2, _usage),
        };
    }

    /// <summary>Prints how every server compares with its pins. Exit 1 on any difference.</summary>
    /// <remarks>
    /// A server with no pins counts as a difference: in CI, against a committed
    /// pins file, it means a server was added without anyone pinning it.
    /// </remarks>
    private static async Task<int> StatusAsync(string[] args)
    {
        await using var startup = await ProxyStartup.LoadAsync(args, listing: true);
        var document = Load(startup.Pins.Path);

        Console.WriteLine($"pins: {startup.Pins.Path}{(document is null ? " (does not exist yet)" : string.Empty)}");

        var result = PinCheck.Run(document, startup.Upstream.Connections.Select(PinSubject.From), DateTimeOffset.UtcNow);
        foreach (var report in result.Reports)
        {
            // Tool names and reasons are the server's text, printed to a
            // terminal: nothing in them may move the cursor or forge a line.
            Console.WriteLine(TerminalText.Printable(Summary(report)));
            foreach (var tool in report.Changed)
            {
                Console.WriteLine($"  changed  {TerminalText.Printable(tool)}");
            }

            foreach (var tool in report.Added)
            {
                Console.WriteLine($"  added    {TerminalText.Printable(tool)}");
            }

            foreach (var tool in report.Removed)
            {
                Console.WriteLine($"  removed  {TerminalText.Printable(tool)}");
            }
        }

        foreach (var missing in startup.Upstream.Unavailable)
        {
            Console.WriteLine($"{missing.Name}: unavailable, not compared ({TerminalText.Printable(missing.Reason)})");
        }

        var differing = result.Reports.Count(r => r.HasDifferences);
        Console.WriteLine(differing == 0 ? "pins match" : $"{differing} server(s) differ from their pins");
        return differing == 0 ? 0 : 1;
    }

    /// <summary>Prints the pinned definitions against the current ones.</summary>
    private static async Task<int> DiffAsync(string[] args, string server, string? tool)
    {
        await using var startup = await ProxyStartup.LoadAsync(args, listing: true);
        var document = Load(startup.Pins.Path) ?? PinsDocument.Empty;

        var subject = PinSubject.From(Connection(startup, server));
        document.EffectiveServers.TryGetValue(server, out var pinned);

        try
        {
            // Lines kept: the diff is the proxy's own layout around JSON the
            // writer already escaped, and a tool name in its headers.
            Console.Write(TerminalText.PrintableLines(PinReview.Diff(pinned, subject, tool)));
        }
        catch (PinsException ex)
        {
            throw new CommandFailedException(1, ex.Message);
        }

        return 0;
    }

    /// <summary>Re-pins a server, some of its tools, or every server.</summary>
    private static async Task<int> AcceptAsync(string[] args, string? server, IReadOnlyList<string> tools)
    {
        await using var startup = await ProxyStartup.LoadAsync(args, listing: true);
        var document = Load(startup.Pins.Path) ?? PinsDocument.Empty;
        var now = DateTimeOffset.UtcNow;

        var connections = server is null
            ? [.. startup.Upstream.Connections]
            : new[] { Connection(startup, server) };

        var accepted = new List<(string Server, AcceptedPin Pin)>();
        try
        {
            foreach (var connection in connections)
            {
                var subject = PinSubject.From(connection);
                var (updated, pins) = tools.Count == 0
                    ? PinReview.AcceptServer(document, subject, now)
                    : PinReview.AcceptTools(document, subject, tools, now);

                document = updated;
                accepted.AddRange(pins.Select(pin => (connection.Name, pin)));
            }

            PinsFile.Save(startup.Pins.Path, document);
        }
        catch (PinsException ex)
        {
            throw new CommandFailedException(1, ex.Message);
        }

        foreach (var (name, pin) in accepted)
        {
            Console.WriteLine($"{name}: {(pin.Removed ? "dropped the pin of" : "accepted")} {TerminalText.Printable(pin.Tool)}");
            await startup.Audit.WriteAsync(PinAudit.Accepted(name, pin, now), CancellationToken.None);
        }

        Console.WriteLine(accepted.Count == 0
            ? $"Nothing to accept; {startup.Pins.Path} is up to date."
            : $"Wrote {startup.Pins.Path}.");
        return 0;
    }

    /// <summary>Forgets a server's pins without connecting to anything.</summary>
    private static async Task<int> ResetAsync(string server)
    {
        var policyPath = CliPaths.ConfigPath("GUARDRAILS_POLICY", "policy.yaml");
        PolicyDocument policy;
        try
        {
            policy = PolicyLoader.LoadFromFileOrEmpty(policyPath);
        }
        catch (PolicyException ex)
        {
            throw new CommandFailedException(1, $"Invalid policy file '{policyPath}': {ex.Message}");
        }

        var path = PinsFile.ResolvePath(
            policy.EffectiveScanners.EffectivePins, policyPath, Environment.GetEnvironmentVariable, CliHost.Environment.HomeDirectory);

        try
        {
            var document = Load(path) ?? throw new PinsException($"There is no pins file at '{path}'.");
            PinsFile.Save(path, PinReview.Reset(document, server));
        }
        catch (PinsException ex)
        {
            throw new CommandFailedException(1, ex.Message);
        }

        await using (var audit = new JsonlAuditSink(CliPaths.ConfigPath("GUARDRAILS_AUDIT", "audit.jsonl")))
        {
            await audit.WriteAsync(PinAudit.Reset(server, DateTimeOffset.UtcNow), CancellationToken.None);
        }

        Console.WriteLine($"Forgot the pins of server '{server}' in {path}; it is pinned again the next time the proxy serves.");
        return 0;
    }

    private static string Summary(ServerPinReport report)
    {
        if (report.FirstSeen)
        {
            return $"{report.Server}: not pinned yet ({report.Current.Count} tools)";
        }

        if (report.IdentityChanged)
        {
            return $"{report.Server}: a different program from the one pinned (pinned from: {report.PinnedHint}; now: {report.CurrentHint})";
        }

        return report.HasDifferences
            ? $"{report.Server}: {report.Changed.Count} changed, {report.Added.Count} added, {report.Removed.Count} removed"
            : $"{report.Server}: matches its pins ({report.Current.Count} tools)";
    }

    private static PinsDocument? Load(string path)
    {
        try
        {
            return PinsFile.Load(path);
        }
        catch (PinsException ex)
        {
            throw new CommandFailedException(1, ex.Message);
        }
    }

    private static UpstreamConnection Connection(ProxyStartup startup, string server) =>
        startup.Upstream.Connections.FirstOrDefault(c => c.Name == server)
        ?? throw new CommandFailedException(
            1,
            $"No connected server is named '{server}'. Connected: " +
            string.Join(", ", startup.Upstream.Connections.Select(c => c.Name)) + ".");

    /// <summary>The words after <c>pins</c>, without flags or the values of flags that take one.</summary>
}
