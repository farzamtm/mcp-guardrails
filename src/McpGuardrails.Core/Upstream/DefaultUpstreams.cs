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
    /// The official filesystem server, sandboxed to a scratch directory.
    /// </summary>
    public static IReadOnlyList<UpstreamServerConfig> Create(string sandboxPath) =>
    [
        new UpstreamServerConfig
        {
            Name = "fs",
            Command = "npx",
            Arguments = ["-y", "@modelcontextprotocol/server-filesystem", sandboxPath],
        },
    ];
}
