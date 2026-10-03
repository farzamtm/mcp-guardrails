using System.Reflection;

namespace McpGuardrails.Core.Hosting;

/// <summary>
/// The version the proxy reports as its MCP server version and OTel service.version.
/// </summary>
/// <remarks>
/// Read from the assembly rather than written as a constant, because the release
/// workflow stamps the tag with <c>-p:Version=</c> and a constant would ignore it:
/// a trace and a client's server list would name a version that was never built.
/// The attribute lookup is AOT-safe - attributes are metadata the compiler keeps,
/// not reflection over members the trimmer might remove.
/// </remarks>
public static class ProxyVersion
{
    /// <summary>What is reported when the assembly carries no usable version.</summary>
    public const string Unknown = "0.0.0";

    /// <summary>The version stamped on <paramref name="assembly"/>.</summary>
    public static string Of(Assembly assembly)
    {
        ArgumentNullException.ThrowIfNull(assembly);

        return Normalize(assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>());
    }

    /// <remarks>Null when the assembly was built without the attribute.</remarks>
    internal static string Normalize(AssemblyInformationalVersionAttribute? attribute) =>
        Normalize(attribute?.InformationalVersion);

    /// <summary>
    /// Drops the <c>+commit</c> build metadata the SDK appends.
    /// </summary>
    /// <remarks>
    /// The commit hash is useful in a crash report but noise in a server list,
    /// and semver says build metadata does not distinguish versions anyway.
    /// </remarks>
    internal static string Normalize(string? informationalVersion)
    {
        var version = informationalVersion?.Split('+', 2)[0].Trim();

        return string.IsNullOrEmpty(version) ? Unknown : version;
    }
}
