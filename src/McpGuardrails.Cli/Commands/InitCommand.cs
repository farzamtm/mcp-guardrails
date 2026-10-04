using McpGuardrails.Core.Packs;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Cli.Commands;

/// <summary>
/// <c>init</c>: writes a policy file from the built-in packs.
/// </summary>
/// <remarks>
/// <c>--pack github=gh</c> applies a pack to a named server; <c>--pack github</c>
/// applies it to every configured server it recognizes; no <c>--pack</c> at all
/// applies whichever pack recognizes each server. <c>--list</c> shows the packs.
///
/// Writes to <c>-o &lt;path&gt;</c>, else the policy path the proxy would read,
/// and <c>-o -</c> prints it. An existing file is never replaced silently: if
/// it differs, the diff is printed and <c>--force</c> is needed, because the
/// user may have edited it and a newer pack is a change worth reading. Messages
/// go to stderr so that <c>-o -</c> output is the file and nothing else.
/// </remarks>
internal sealed class InitCommand : ICliCommand
{
    public async Task<int> RunAsync(string[] args)
    {
        var catalog = PackCatalog.BuiltIn;

        if (CliArgs.Has(args, "--list"))
        {
            foreach (var pack in catalog.All)
            {
                Console.WriteLine($"{pack.Name,-12} v{pack.Version}  {pack.Description}");
                Console.WriteLine($"{string.Empty,-16}recognizes: {string.Join(", ", pack.Recognizes)}");
            }

            return 0;
        }

        var requests = CliArgs.Values(args, "--pack").Select(PackRequest.Parse).ToList();
        var selection = PackSelection.Resolve(catalog, requests, LoadServers(args));

        foreach (var warning in selection.Warnings)
        {
            await Console.Error.WriteLineAsync($"warning: {warning}");
        }

        if (selection.Errors.Count > 0)
        {
            throw new CommandFailedException(1, string.Join(Environment.NewLine, selection.Errors.Select(e => $"error: {e}")));
        }

        var policy = PolicyComposer.Compose(selection.Assignments, selection.Unassigned);
        foreach (var assignment in selection.Assignments)
        {
            await Console.Error.WriteLineAsync($"pack {assignment.Pack.Name} -> server '{assignment.Server}' ({assignment.Reason})");
        }

        var output = CliArgs.Value(args, "-o") ?? CliPaths.ConfigPath("GUARDRAILS_POLICY", "policy.yaml");
        if (output == "-")
        {
            Console.Write(policy);
            return 0;
        }

        if (File.Exists(output))
        {
            var existing = await File.ReadAllTextAsync(output);
            if (existing.ReplaceLineEndings("\n") == policy)
            {
                await Console.Error.WriteLineAsync($"{output} is already up to date.");
                return 0;
            }

            if (!CliArgs.Has(args, "--force"))
            {
                await Console.Error.WriteLineAsync(LineDiff.Format(existing.ReplaceLineEndings("\n"), policy));
                throw new CommandFailedException(
                    1,
                    $"{output} exists and differs from what the packs produce (diff above). " +
                    "Review it, then re-run with --force to replace it, or pick another path with -o.");
            }
        }

        WriteAtomically(output, policy);
        await Console.Error.WriteLineAsync($"Wrote {output}. Check it with: mcp-guardrails validate --policy {output}");
        return 0;
    }

    /// <summary>The servers init matches packs against.</summary>
    /// <remarks>
    /// With no servers file, the built-in filesystem server: that is what the
    /// proxy would serve, so the filesystem pack still finds it.
    /// </remarks>
    private static IReadOnlyList<UpstreamServerConfig> LoadServers(string[] args)
    {
        if (CliServers.Path(args) is not { } path)
        {
            return DefaultUpstreams.Create(Path.Combine(Path.GetTempPath(), "guardrails-sandbox"));
        }

        var result = ServersLoader.LoadFile(path, CliHost.Environment);

        // Packs are matched against what the proxy would actually run, so a
        // servers file the proxy would refuse is fixed first.
        return result.IsValid
            ? result.Servers
            : throw new CommandFailedException(
                1,
                $"The servers file '{path}' has errors; fix them first (mcp-guardrails validate lists them):" +
                Environment.NewLine + string.Join(Environment.NewLine, result.Errors.Select(e => $"  {e}")));
    }

    /// <summary>Writes beside the target and renames, so a crash never leaves half a policy.</summary>
    private static void WriteAtomically(string path, string text)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        Directory.CreateDirectory(directory);

        var temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        File.WriteAllText(temporary, text);
        File.Move(temporary, path, overwrite: true);
    }
}
