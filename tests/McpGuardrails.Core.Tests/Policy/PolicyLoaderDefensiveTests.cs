using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Serialization;
using YamlDotNet.RepresentationModel;

namespace McpGuardrails.Core.Tests.Policy;

/// <summary>
/// Covers the loader's defensive branches that ARE reachable from a test.
/// </summary>
/// <remarks>
/// YamlAliasNode is internal to YamlDotNet, so the "unsupported node type" arm of
/// ToJsonNode cannot be provoked at all; that method is excluded from coverage
/// with a justification instead of being tested here.
/// </remarks>
public sealed class PolicyLoaderDefensiveTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), $"guardrails-defensive-{Guid.NewGuid():N}");

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public void ToJsonValue_MapsANullScalarToJsonNull()
    {
        // YamlDotNet gives "" rather than null for an empty scalar, so this guard
        // is not reachable through Parse - but it is reachable directly, and a
        // null here would otherwise become a NullReferenceException.
        var scalar = new YamlScalarNode(value: null);

        Assert.Null(YamlJson.ToJsonValue(scalar));
    }

    /// <summary>
    /// Covers the IOException path, which is distinct from the permission path.
    /// </summary>
    /// <remarks>
    /// Holding the file open with FileShare.None makes the loader's read fail
    /// with IOException on every platform, unlike chmod which is Unix-only. The
    /// point is that a locked or otherwise unreadable policy must be a loud
    /// error, never a silent fall back to "no policy" - that would be a
    /// fail-open.
    /// </remarks>
    [Fact]
    public void LoadFromFileOrEmpty_ReportsALockedFileAsAPolicyError()
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "locked.yaml");
        File.WriteAllText(path, "rules: []");

        using var exclusiveLock = new FileStream(
            path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        var exception = Assert.Throws<PolicyException>(
            () => PolicyLoader.LoadFromFileOrEmpty(path));

        Assert.Contains("Could not read", exception.Message, StringComparison.Ordinal);
    }
}
