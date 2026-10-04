using McpGuardrails.Core.Packs;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Tests.Packs;

/// <summary>
/// The catalog, and the shipped packs themselves: each one loads from the
/// embedded resources, and each passes its own test file.
/// </summary>
public sealed class PackCatalogTests
{
    private static readonly string _packsDirectory = Path.Combine(AppContext.BaseDirectory, "packs");

    public static TheoryData<string> PackTestFiles() =>
        [.. Directory.GetFiles(_packsDirectory, "*.test.yaml").Select(Path.GetFileName).OfType<string>()];

    [Fact]
    public void BuiltIn_HoldsEveryShippedPack()
    {
        var shipped = Directory.GetFiles(_packsDirectory, "*.yaml")
            .Where(path => !path.EndsWith(".test.yaml", StringComparison.Ordinal))
            .Select(path => Path.GetFileNameWithoutExtension(path))
            .Order(StringComparer.Ordinal);

        Assert.Equal(shipped, PackCatalog.BuiltIn.All.Select(pack => pack.Name));
    }

    [Fact]
    public void BuiltIn_EveryPackHasATestFile()
    {
        foreach (var pack in PackCatalog.BuiltIn.All)
        {
            Assert.True(
                File.Exists(Path.Combine(_packsDirectory, $"{pack.Name}.test.yaml")),
                $"pack '{pack.Name}' has no test file");
        }
    }

    [Theory]
    [MemberData(nameof(PackTestFiles))]
    public void ShippedPack_PassesItsOwnTests(string testFile)
    {
        var document = PolicyTestRunner.Parse(File.ReadAllText(Path.Combine(_packsDirectory, testFile)));
        var report = PolicyTestRunner.Run(document, File.ReadAllText(Path.Combine(_packsDirectory, document.Policy!)));

        Assert.True(
            report.Failures.Count == 0,
            string.Join(Environment.NewLine, report.Failures.Select(f => $"{f.Label}: {f.Failure}")));
    }

    [Fact]
    public void BuiltIn_RecognizesTheBuiltInFilesystemServer()
    {
        var server = DefaultUpstreams.Create("/tmp/sandbox")[0];

        Assert.Equal(
            ["filesystem"],
            PackCatalog.BuiltIn.All.Where(pack => pack.Recognize(server) is not null).Select(pack => pack.Name));
    }

    [Fact]
    public void FromTexts_OrdersByName()
    {
        var catalog = PackCatalog.FromTexts([PolicyPackTests.PackText("zeta"), PolicyPackTests.PackText("alpha")]);

        Assert.Equal(["alpha", "zeta"], catalog.All.Select(pack => pack.Name));
    }

    [Fact]
    public void FromTexts_DuplicateNames_Throws()
    {
        var ex = Assert.Throws<PackException>(() =>
            PackCatalog.FromTexts([PolicyPackTests.PackText("same"), PolicyPackTests.PackText("same")]));

        Assert.Contains("Two packs are named 'same'", ex.Message);
    }

    [Fact]
    public void Find_IsCaseInsensitive_AndReturnsNullForUnknown()
    {
        var catalog = PackCatalog.FromTexts([PolicyPackTests.PackText("demo")]);

        Assert.Equal("demo", catalog.Find("DEMO")?.Name);
        Assert.Null(catalog.Find("missing"));
    }
}
