using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Packs;

/// <summary>One pack applied to one server.</summary>
/// <param name="Pack">The pack.</param>
/// <param name="Server">The server name its placeholder becomes.</param>
/// <param name="Reason">Why this server got this pack, for <c>init</c> to print.</param>
public sealed record PackAssignment(PolicyPack Pack, string Server, string Reason);

/// <summary>A <c>--pack</c> argument: <c>github</c> or <c>github=gh</c>.</summary>
/// <param name="Pack">The pack's name.</param>
/// <param name="Server">The server named after <c>=</c>, or null to find it.</param>
public sealed record PackRequest(string Pack, string? Server)
{
    /// <summary>Splits <c>pack=server</c>.</summary>
    public static PackRequest Parse(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var equals = value.IndexOf('=', StringComparison.Ordinal);
        return equals < 0
            ? new PackRequest(value, null)
            : new PackRequest(value[..equals], value[(equals + 1)..]);
    }
}

/// <summary>What <see cref="PackSelection.Resolve"/> decided.</summary>
/// <param name="Assignments">Packs to apply, in the order they will be written.</param>
/// <param name="Unassigned">Configured servers no pack covers.</param>
/// <param name="Warnings">Problems that do not stop <c>init</c>.</param>
/// <param name="Errors">Problems that do; empty when there are none.</param>
public sealed record PackSelectionResult(
    IReadOnlyList<PackAssignment> Assignments,
    IReadOnlyList<string> Unassigned,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Errors);

/// <summary>Works out which pack goes with which server.</summary>
/// <remarks>
/// Pure: the catalog, the requests and the configured servers in, a decision
/// out. Every problem is collected rather than thrown, so <c>init</c> can
/// report them all at once like <c>validate</c> does.
/// </remarks>
public static class PackSelection
{
    /// <summary>Resolves the requests against the servers.</summary>
    /// <param name="catalog">The packs available.</param>
    /// <param name="requests">
    /// The <c>--pack</c> arguments. Empty means "suggest": every configured
    /// server a pack recognizes gets that pack.
    /// </param>
    /// <param name="servers">The configured servers, used to find unnamed servers.</param>
    public static PackSelectionResult Resolve(
        PackCatalog catalog,
        IReadOnlyList<PackRequest> requests,
        IReadOnlyList<UpstreamServerConfig> servers)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(requests);
        ArgumentNullException.ThrowIfNull(servers);

        var assignments = new List<PackAssignment>();
        var warnings = new List<string>();
        var errors = new List<string>();
        var names = servers.Select(server => server.Name).ToList();

        if (requests.Count == 0)
        {
            assignments.AddRange(Suggest(catalog, servers));
            if (assignments.Count == 0)
            {
                errors.Add(
                    "No pack recognizes any configured server. Name one with --pack <pack>=<server>; " +
                    $"the packs are {string.Join(", ", catalog.All.Select(pack => pack.Name))}.");
            }
        }

        foreach (var request in requests)
        {
            if (catalog.Find(request.Pack) is not { } pack)
            {
                errors.Add(
                    $"There is no pack called '{request.Pack}'. " +
                    $"The packs are {string.Join(", ", catalog.All.Select(p => p.Name))}.");
                continue;
            }

            if (request.Server is { } server)
            {
                if (!UpstreamServerConfig.IsValidName(server))
                {
                    errors.Add($"--pack {request.Pack}={server}: '{server}' is not a valid server name.");
                    continue;
                }

                if (!names.Contains(server, StringComparer.Ordinal))
                {
                    // A warning, not an error: writing the policy before the
                    // servers file is a reasonable order to do things in.
                    // validate repeats it once both exist.
                    warnings.Add(
                        $"No configured server is called '{server}', so the {pack.Name} rules will " +
                        "not apply until one is.");
                }

                assignments.Add(new PackAssignment(pack, server, "named on the command line"));
                continue;
            }

            var recognized = servers
                .Select(s => (s.Name, Match: pack.Recognize(s)))
                .Where(match => match.Match is not null)
                .ToList();
            if (recognized.Count == 0)
            {
                errors.Add(
                    $"Pack '{pack.Name}' recognizes none of the configured servers " +
                    $"({(names.Count == 0 ? "none" : string.Join(", ", names))}). " +
                    $"Name the server: --pack {pack.Name}=<server>.");
                continue;
            }

            assignments.AddRange(recognized.Select(match =>
                new PackAssignment(pack, match.Name, $"recognized {match.Match}")));
        }

        foreach (var group in assignments.GroupBy(a => a.Server, StringComparer.Ordinal).Where(g => g.Count() > 1))
        {
            // Both would be scoped to the same server, so the first pack's
            // catch-all would decide every call and the second would be dead
            // text that looks like it protects something.
            errors.Add(
                $"Server '{group.Key}' would get more than one pack " +
                $"({string.Join(", ", group.Select(a => a.Pack.Name))}). Give each server one pack.");
        }

        var assigned = assignments.Select(a => a.Server).ToHashSet(StringComparer.Ordinal);
        return new PackSelectionResult(
            errors.Count == 0 ? assignments : [],
            [.. names.Where(name => !assigned.Contains(name))],
            warnings,
            errors);
    }

    private static IEnumerable<PackAssignment> Suggest(PackCatalog catalog, IReadOnlyList<UpstreamServerConfig> servers)
    {
        foreach (var server in servers)
        {
            // First by name: recognizers are whole-word, so two packs claiming
            // one server would be a catalog bug, and a deterministic pick beats
            // an error the user cannot fix.
            var match = catalog.All
                .Select(pack => (Pack: pack, Match: pack.Recognize(server)))
                .FirstOrDefault(candidate => candidate.Match is not null);

            if (match.Pack is not null)
            {
                yield return new PackAssignment(match.Pack, server.Name, $"recognized {match.Match}");
            }
        }
    }
}
