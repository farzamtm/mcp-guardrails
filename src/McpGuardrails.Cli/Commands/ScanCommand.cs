using System.Text.Json;
using McpGuardrails.Core.Scanners;
using McpGuardrails.Core.Serialization;
using McpGuardrails.Core.Upstream;
using Microsoft.Extensions.Logging;

namespace McpGuardrails.Cli.Commands;

/// <summary>
/// <c>scan</c>: connects to servers, checks their tool definitions, prints a
/// report and exits. Nothing is served.
/// </summary>
/// <remarks>
/// Deliberately independent of the policy, the pins file and the audit log: a
/// scan is a look at what a server advertises, and its result should be the same
/// on every machine - not depend on what one operator's policy happens to switch
/// off - and leave no trace in files the proxy treats as state.
///
/// Exit codes: 0 when every server was scanned and nothing was found, 1 when
/// something was found or a server could not be scanned, 2 for a bad command line.
/// </remarks>
internal sealed class ScanCommand : ICliCommand
{
    public async Task<int> RunAsync(string[] args)
    {
        ScanOptions options;
        try
        {
            options = ScanOptions.Parse(args);
        }
        catch (ScanOptionsException ex)
        {
            throw new CommandFailedException(2, ex.Message);
        }

        var servers = LoadServers(options);

        using var loggerFactory = LoggerFactory.Create(logging => CliLogging.ToStandardError(logging, listing: true));
        var log = loggerFactory.CreateLogger("McpGuardrails.Scan");
        foreach (var warning in servers.Warnings)
        {
            log.LogWarning("{Warning}", warning);
        }

        UpstreamRegistry upstream;
        try
        {
            upstream = await UpstreamRegistry.ConnectAsync(servers.Servers, loggerFactory);
        }
        catch (UpstreamConnectionException ex)
        {
            throw new CommandFailedException(1, $"{ex.Message} Nothing was scanned.");
        }

        await using (upstream)
        {
            var report = ScanReport.Build(
                upstream.Connections
                    .OrderBy(connection => connection.Name, StringComparer.Ordinal)
                    .Select(connection => (
                        connection.Config,
                        connection.Name,
                        (IReadOnlyList<ModelContextProtocol.Protocol.Tool>)[.. connection.Tools.Select(tool => tool.ProtocolTool)])),
                upstream.Unavailable.Select(missing => new UnscannedServer { Name = missing.Name, Reason = missing.Reason }));

            // stdout, not stderr: scan is not an MCP server, so stdout is free,
            // and the report is the command's output - the thing to redirect.
            Console.Write(options.Json
                ? JsonSerializer.Serialize(report, ScanJsonContext.Default.ScanReport) + Environment.NewLine
                : ScanReportText.Render(report));

            return report.IsClean ? 0 : 1;
        }
    }

    /// <summary>
    /// The one target named on the command line, else the servers the proxy
    /// would serve: the servers file, or the built-in filesystem server.
    /// </summary>
    private static ServersLoadResult LoadServers(ScanOptions options)
    {
        string source;
        ServersLoadResult result;

        if (options.TargetDocument is { } target)
        {
            source = "the scan target";
            result = ServersLoader.Parse(target, Directory.GetCurrentDirectory(), CliHost.Environment);
        }
        else if ((options.ServersPath ?? CliServers.Path([])) is { } path)
        {
            source = $"servers file '{path}'";
            result = ServersLoader.LoadFile(path, CliHost.Environment);
        }
        else
        {
            var sandbox = Environment.GetEnvironmentVariable("GUARDRAILS_SANDBOX")
                          ?? Path.Combine(Path.GetTempPath(), "guardrails-sandbox");
            Directory.CreateDirectory(sandbox);
            return new ServersLoadResult(DefaultUpstreams.Create(sandbox), [], [], []);
        }

        if (!result.IsValid)
        {
            throw new CommandFailedException(
                1,
                $"Invalid {source}:{Environment.NewLine}" +
                string.Join(Environment.NewLine, result.Errors.Select(e => $"  - {e}")));
        }

        return result;
    }
}
