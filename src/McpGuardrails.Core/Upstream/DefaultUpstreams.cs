namespace McpGuardrails.Core.Upstream;

/// <summary>
/// Hardcoded upstream servers used while the proxy has no config file yet.
/// </summary>
/// <remarks>
/// Step 5 replaces this with the YAML policy/config loader. It exists so the
/// earlier steps stay runnable without also building configuration parsing -
/// one new concept at a time.
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
