using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Cli.Commands;

/// <summary>
/// <c>validate</c>: checks the servers file and the policy without spawning
/// anything, and reports every problem at once.
/// </summary>
/// <remarks>
/// Exit 0 when both files are usable, 1 when either has an error - so it can gate
/// a CI job on a committed servers file. Unlike <c>list-upstream</c> it never
/// launches a server, so it is safe to run on a file nobody has reviewed yet.
/// Output goes to stdout: this command is not an MCP server, so stdout is not the
/// JSON-RPC wire here.
/// </remarks>
internal sealed class ValidateCommand : ICliCommand
{
    public Task<int> RunAsync(string[] args)
    {
        var errors = 0;
        var serverNames = new List<string>();

        var serversPath = CliServers.Path(args);
        if (serversPath is null)
        {
            Console.WriteLine(
                $"servers: no servers file (looked for --servers, {ServersLoader.FileVariable} and " +
                $"{CliPaths.DefaultPath(CliServers.DefaultFileName)}); the built-in filesystem server would be used.");
            serverNames.Add("fs");
        }
        else
        {
            var result = ServersLoader.LoadFile(serversPath, CliHost.Environment);
            Console.WriteLine($"servers: {serversPath}");

            foreach (var server in result.Servers)
            {
                Console.WriteLine($"  {server.Name,-20} {server.Transport.ToWireName(),-5}  {server.DisplayTemplate}");
                serverNames.Add(server.Name);
            }

            foreach (var name in result.Disabled)
            {
                Console.WriteLine($"  {name,-20} disabled");
            }

            CliServers.Report(result, Console.Out);
            errors += result.Errors.Count;
        }

        var policyPath = CliArgs.Value(args, "--policy") ?? CliPaths.ConfigPath("GUARDRAILS_POLICY", "policy.yaml");
        try
        {
            var policy = PolicyLoader.LoadFromFileOrEmpty(policyPath);
            Console.WriteLine(File.Exists(policyPath)
                ? $"policy: {policyPath} ({policy.EffectiveRules.Count} rules)"
                : $"policy: no file at {policyPath}; every call would be allowed and audited.");

            foreach (var rule in policy.RulesMatchingNoServer(serverNames))
            {
                Console.WriteLine($"warning: policy rule '{rule}' has a 'server:' pattern that matches no configured server, so it never applies.");
            }
        }
        catch (PolicyException ex)
        {
            Console.WriteLine($"error: invalid policy file '{policyPath}': {ex.Message}");
            errors++;
        }

        Console.WriteLine(errors == 0 ? "valid" : $"invalid: {errors} error(s)");
        return Task.FromResult(errors == 0 ? 0 : 1);
    }
}
