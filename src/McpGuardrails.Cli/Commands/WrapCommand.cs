using System.Text;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Cli.Commands;

/// <summary>
/// <c>wrap --client &lt;client&gt;</c>: puts the proxy in front of every server a
/// client is configured with, in one step.
/// </summary>
/// <remarks>
/// Imports the client's servers into a servers file, backs the client config up,
/// and replaces its server list with one entry that launches the proxy. The
/// lifted secrets go into that entry's env - the same file they were already in -
/// so they reach the proxy without ever being written to the servers file.
/// <c>--dry-run</c> prints what would change and writes nothing.
/// <c>unwrap</c> undoes it.
/// </remarks>
internal sealed class WrapCommand : ICliCommand
{
    public async Task<int> RunAsync(string[] args)
    {
        var client = CliArgs.Client(args, "--client");
        var configPath = CliClientPaths.Resolve(client, args);
        var serversPath = Path.GetFullPath(CliArgs.Value(args, "-o") ?? CliPaths.DefaultPath(CliServers.DefaultFileName));
        var policyPath = Path.GetFullPath(CliArgs.Value(args, "--policy") ?? CliPaths.ConfigPath("GUARDRAILS_POLICY", "policy.yaml"));
        var dryRun = CliArgs.Has(args, "--dry-run");

        var binary = Environment.ProcessPath
                     ?? throw new CommandFailedException(1, "Cannot tell where this executable is, so the client could not launch it.");

        // Run as `dotnet McpGuardrails.Cli.dll`, the process is dotnet itself,
        // and a client launching that would get the SDK's help text.
        if (string.Equals(Path.GetFileNameWithoutExtension(binary), "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            throw new CommandFailedException(1, "Run wrap from the installed mcp-guardrails executable, not through 'dotnet', so the client can launch it.");
        }

        var originalBytes = await File.ReadAllBytesAsync(configPath);
        var originalText = Encoding.UTF8.GetString(originalBytes);

        ImportResult imported;
        string wrapped;
        try
        {
            imported = ClientConfigs.Import(client, originalText, configPath, CliHost.Environment);
            wrapped = ClientConfigs.Wrap(client, originalText, configPath, binary, serversPath, policyPath, imported.Secrets);
        }
        catch (ClientConfigException ex)
        {
            throw new CommandFailedException(1, ex.Message);
        }

        // The proxy will see the lifted secrets in its environment; validate as
        // it will, so a server that could never start fails here, before the
        // client config is touched, rather than on the client's next launch.
        var secrets = imported.Secrets.ToDictionary(s => s.Variable, s => s.Value, StringComparer.Ordinal);
        var host = CliHost.Environment;
        var validation = ServersLoader.Parse(
            imported.ServersYaml,
            Path.GetDirectoryName(serversPath)!,
            new HostEnvironment
            {
                GetVariable = name => secrets.TryGetValue(name, out var value) ? value : host.GetVariable(name),
                VariableNames = () => host.VariableNames().Concat(secrets.Keys).Distinct(StringComparer.Ordinal),
                FileExists = host.FileExists,
                DirectoryExists = host.DirectoryExists,
                ReadAllText = host.ReadAllText,
                GetUnixFileMode = host.GetUnixFileMode,
                HomeDirectory = host.HomeDirectory,
                IsWindows = host.IsWindows,
                IsMacOS = host.IsMacOS,
            });

        CliServers.Report(validation, Console.Error);
        if (!validation.IsValid)
        {
            throw new CommandFailedException(1, $"Not wrapping {configPath}: the imported servers would not start. Nothing was changed.");
        }

        if (dryRun)
        {
            Console.WriteLine($"# Would write {serversPath}:");
            Console.Write(imported.ServersYaml);
            Console.WriteLine();
            Console.WriteLine($"# Would back up and rewrite {configPath}:");
            Console.Write(Mask(LineDiff.Format(originalText, wrapped), imported.Secrets));
            await ImportCommand.WriteNotesAsync(imported with { Secrets = [] });
            return 0;
        }

        string backup;
        try
        {
            backup = ClientConfigFiles.ApplyWrap(configPath, originalBytes, wrapped, serversPath, imported.ServersYaml, DateTimeOffset.UtcNow);
        }
        catch (ClientConfigException ex)
        {
            throw new CommandFailedException(1, ex.Message);
        }

        await ImportCommand.WriteNotesAsync(imported with { Secrets = [] });
        Console.WriteLine($"Wrapped {imported.ServerCount} server(s) from {configPath}.");
        Console.WriteLine($"  servers file: {serversPath}");
        Console.WriteLine($"  backup:       {backup}");
        if (imported.Secrets.Count > 0)
        {
            Console.WriteLine($"  {imported.Secrets.Count} secret(s) moved from the servers' entries into the proxy entry's env.");
        }

        Console.WriteLine($"Restart {client.Name} to use it. Undo with: mcp-guardrails unwrap --client {client.Name}");
        return 0;
    }

    /// <summary>The diff with every lifted secret's value hidden: it is printed to a terminal.</summary>
    private static string Mask(string text, IReadOnlyList<LiftedSecret> secrets) =>
        secrets.Aggregate(text, (current, secret) =>
            current.Replace(secret.Value, $"<{secret.Variable}>", StringComparison.Ordinal));
}
