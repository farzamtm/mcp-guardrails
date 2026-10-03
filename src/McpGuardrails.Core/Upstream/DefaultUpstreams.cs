namespace McpGuardrails.Core.Upstream;

/// <summary>
/// The downstream servers the proxy connects to.
/// </summary>
/// <remarks>
/// Fixed in code: there is no configuration file for upstream servers, and the
/// policy file deliberately does not describe them - it says what calls may do,
/// not where they go. The one server is sandboxed by its own launch arguments,
/// so the policy is a layer above that containment rather than the only one.
/// </remarks>
public static class DefaultUpstreams
{
    /// <summary>
    /// npm package of the official filesystem server.
    /// </summary>
    public const string FilesystemServerPackage = "@modelcontextprotocol/server-filesystem";

    /// <summary>
    /// Exact npm version of <see cref="FilesystemServerPackage"/> that is spawned.
    /// </summary>
    /// <remarks>
    /// Pinned because <c>npx -y</c> with a bare package name runs whatever npm
    /// published most recently, on every start: a supply-chain path straight
    /// into a security proxy, and smoke/CI runs that are not reproducible.
    /// To bump: pick a release from
    /// <c>npm view @modelcontextprotocol/server-filesystem time --json</c> that
    /// has been public for more than a few days (fresh releases are where a
    /// hijacked publish lives until someone notices), change this constant and
    /// the test that asserts it, then run <c>scripts/preflight.sh</c> - its
    /// smoke test drives the real server end to end behind the proxy.
    /// </remarks>
    public const string FilesystemServerVersion = "2026.8.31";

    /// <summary>
    /// The official filesystem server, sandboxed to a scratch directory.
    /// </summary>
    public static IReadOnlyList<UpstreamServerConfig> Create(string sandboxPath) =>
    [
        new UpstreamServerConfig
        {
            Name = "fs",
            Command = "npx",
            Arguments =
            [
                "-y",
                $"{FilesystemServerPackage}@{FilesystemServerVersion}",
                sandboxPath,
            ],
        },
    ];
}
