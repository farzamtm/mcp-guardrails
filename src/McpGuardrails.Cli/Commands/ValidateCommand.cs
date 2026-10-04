using McpGuardrails.Core.Pins;
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
                if (server.Reach() is { } reach)
                {
                    Console.WriteLine($"  {"",-20}        can reach: {reach}");
                }

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

            errors += CheckPins(policy, policyPath);
        }
        catch (PolicyException ex)
        {
            Console.WriteLine($"error: invalid policy file '{policyPath}': {ex.Message}");
            errors++;
        }

        Console.WriteLine(errors == 0 ? "valid" : $"invalid: {errors} error(s)");
        return Task.FromResult(errors == 0 ? 0 : 1);
    }

    /// <summary>Checks the pins file parses, when pinning is on and there is one.</summary>
    /// <remarks>
    /// The proxy refuses to start on a pins file it cannot read, so validate
    /// should say so first. Only parsed: comparing it needs the servers running.
    /// </remarks>
    private static int CheckPins(PolicyDocument policy, string policyPath)
    {
        var settings = policy.EffectiveScanners.EffectivePins;
        if (settings.IsOff)
        {
            Console.WriteLine("pins: off");
            return 0;
        }

        var path = PinsFile.ResolvePath(
            settings, policyPath, Environment.GetEnvironmentVariable, CliHost.Environment.HomeDirectory);
        try
        {
            var document = PinsFile.Load(path);
            Console.WriteLine(document is null
                ? $"pins: no file at {path} yet; servers are pinned the first time the proxy serves."
                : $"pins: {path} ({document.EffectiveServers.Count} servers pinned)");
            return 0;
        }
        catch (PinsException ex)
        {
            Console.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }
}
