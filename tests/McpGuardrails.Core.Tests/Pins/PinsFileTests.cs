using McpGuardrails.Core.Pins;
using static McpGuardrails.Core.Tests.Pins.PinTestData;

namespace McpGuardrails.Core.Tests.Pins;

/// <summary>
/// Tests for reading and writing the pins file, and above all for refusing one
/// that cannot be trusted rather than treating it as empty.
/// </summary>
public sealed class PinsFileTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("guardrails-pins-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private string PathIn(string name) => Path.Combine(_directory, name);

    private static readonly string _hash = "sha256:" + new string('a', 64);

    private static string ValidText(string extra = "") => $$"""
        {
          "version": 1,
          "servers": {
            "fs": {
              "identity": "{{Identity}}",
              "identity_hint": "npx server",
              "pinned_at": "2026-10-04T10:00:00Z",
              "tools": { "read": { "hash": "{{_hash}}" } }{{extra}}
            }
          }
        }
        """;

    // ---------------------------------------------------------------- paths

    private static string Resolve(PinSettings settings, string? variable = null) =>
        PinsFile.ResolvePath(
            settings,
            "/etc/guardrails/policy.yaml",
            name => name == PinsFile.PathVariable ? variable : null,
            "/home/me");

    [Fact]
    public void Path_DefaultsToTheProxysHomeDirectory()
    {
        Assert.Equal(Path.Combine("/home/me", ".mcp-guardrails", "pins.json"), Resolve(PinSettings.Default));
    }

    [Fact]
    public void Path_FromTheEnvironment_WinsOverThePolicy()
    {
        Assert.Equal("/tmp/p.json", Resolve(new PinSettings { File = "/srv/pins.json" }, "/tmp/p.json"));

        // Set but empty is the same as unset, not a file named "".
        Assert.Equal("/srv/pins.json", Resolve(new PinSettings { File = "/srv/pins.json" }, ""));
    }

    [Fact]
    public void Path_FromThePolicy_ExpandsHome_AndResolvesAgainstThePolicyFile()
    {
        Assert.Equal(Path.Combine("/home/me", "team/pins.json"), Resolve(new PinSettings { File = "~/team/pins.json" }));
        Assert.Equal(Path.GetFullPath("/etc/guardrails/pins.json"), Resolve(new PinSettings { File = "pins.json" }));
        Assert.Equal("/srv/pins.json", Resolve(new PinSettings { File = "/srv/pins.json" }));
    }

    [Fact]
    public void Path_RejectsNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => PinsFile.ResolvePath(null!, "p", _ => null, "h"));
        Assert.Throws<ArgumentNullException>(() => PinsFile.ResolvePath(PinSettings.Default, null!, _ => null, "h"));
        Assert.Throws<ArgumentNullException>(() => PinsFile.ResolvePath(PinSettings.Default, "p", null!, "h"));
        Assert.Throws<ArgumentNullException>(() => PinsFile.ResolvePath(PinSettings.Default, "p", _ => null, null!));
    }

    // ---------------------------------------------------------------- load

    [Fact]
    public void Load_OfAMissingFile_IsNull()
    {
        Assert.Null(PinsFile.Load(PathIn("absent.json")));
        Assert.Null(PinsFile.Load(PathIn("no-such-dir/pins.json")));
    }

    [Fact]
    public void Load_OfSomethingUnreadable_Throws()
    {
        // A directory where the file should be: exists, cannot be read.
        var ex = Assert.Throws<PinsException>(() => PinsFile.Load(_directory));
        Assert.Contains("Could not read", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_ReadsAValidFile()
    {
        File.WriteAllText(PathIn("pins.json"), ValidText());

        var document = PinsFile.Load(PathIn("pins.json"))!;

        var server = document.EffectiveServers["fs"];
        Assert.Equal(Identity, server.Identity);
        Assert.Equal("npx server", server.IdentityHint);
        Assert.Equal(PinnedAt, server.PinnedAt);
        Assert.Equal(_hash, server.EffectiveTools["read"].Hash);
        Assert.Null(server.EffectiveTools["read"].Definition);
    }

    [Theory]
    [InlineData("null", "empty")]
    [InlineData("{", "not valid")]
    [InlineData("""{"version":1,"servers":{},"extra":true}""", "extra")]
    [InlineData("""{"servers":{}}""", "'version' is missing")]
    [InlineData("""{"version":2}""", "version 2 is not supported")]
    [InlineData("""{"version":1,"servers":{"bad_name":{"identity":"x"}}}""", "not a valid server name")]
    [InlineData("""{"version":1,"servers":{"fs":null}}""", "no valid 'identity'")]
    [InlineData("""{"version":1,"servers":{"fs":{"identity":"sha256:abc"}}}""", "no valid 'identity'")]
    public void Parse_RefusesAFileItCannotTrust(string text, string expected)
    {
        var ex = Assert.Throws<PinsException>(() => PinsFile.Parse(text, "pins.json"));

        Assert.Contains(expected, ex.Message, StringComparison.Ordinal);
        Assert.Contains("never replaced automatically", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{ "read": null }""")]
    [InlineData("""{ "read": { "hash": "md5:x" } }""")]
    [InlineData("""{ "read": { "hash": "sha256:aaaa", "definition": "x" } }""")]
    public void Parse_RefusesAToolWithoutAValidHash(string tools)
    {
        var text = "{\"version\":1,\"servers\":{\"fs\":{\"identity\":\"" + Identity + "\",\"tools\":" + tools + "}}}";

        var ex = Assert.Throws<PinsException>(() => PinsFile.Parse(text, "pins.json"));
        Assert.Contains("tool 'read' of server 'fs'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_AcceptsAServerWithNoToolsKey_AndAFileWithNoServersKey()
    {
        Assert.Empty(PinsFile.Parse("""{"version":1}""", "p").EffectiveServers);
        var document = PinsFile.Parse("{\"version\":1,\"servers\":{\"fs\":{\"identity\":\"" + Identity + "\"}}}", "p");
        Assert.Empty(document.EffectiveServers["fs"].EffectiveTools);
    }

    [Fact]
    public void Parse_RejectsNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => PinsFile.Parse(null!, "p"));
        Assert.Throws<ArgumentNullException>(() => PinsFile.Parse("{}", null!));
        Assert.Throws<ArgumentNullException>(() => PinsFile.Load(null!));
    }

    // ---------------------------------------------------------- serialize

    [Fact]
    public void Serialize_IsIndented_SortedByOrdinal_AndEndsInANewline()
    {
        var document = PinsDocument.Empty
            .With("b-server", Pinned(Identity, Tool("zeta"), Tool("Alpha"), Tool("alpha")))
            .With("A-server", Pinned(Identity));

        var text = PinsFile.Serialize(document);

        Assert.EndsWith("}\n", text, StringComparison.Ordinal);
        Assert.DoesNotContain("\r", text, StringComparison.Ordinal);
        Assert.Contains("\n  \"servers\"", text, StringComparison.Ordinal);
        Assert.True(text.IndexOf("A-server", StringComparison.Ordinal) < text.IndexOf("b-server", StringComparison.Ordinal));
        Assert.True(text.IndexOf("\"Alpha\"", StringComparison.Ordinal) < text.IndexOf("\"alpha\"", StringComparison.Ordinal));
        Assert.True(text.IndexOf("\"alpha\"", StringComparison.Ordinal) < text.IndexOf("\"zeta\"", StringComparison.Ordinal));

        var reread = PinsFile.Parse(text, "p");
        Assert.Equal(text, PinsFile.Serialize(reread));
    }

    [Fact]
    public void Serialize_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => PinsFile.Serialize(null!));
    }

    // ---------------------------------------------------------------- save

    [Fact]
    public void Save_CreatesTheDirectory_AndReplacesTheFileWhole()
    {
        var path = PathIn("nested/dir/pins.json");

        PinsFile.Save(path, PinsDocument.Empty.With("fs", Pinned(Identity, Tool("read"))));
        PinsFile.Save(path, PinsDocument.Empty.With("gh", Pinned(Identity, Tool("issue"))));

        var document = PinsFile.Load(path)!;
        Assert.Equal(["gh"], document.EffectiveServers.Keys);
        Assert.Single(Directory.GetFiles(Path.GetDirectoryName(path)!));
    }

    [Fact]
    public void Save_WhereTheDirectoryCannotBeCreated_Throws()
    {
        var file = PathIn("a-file");
        File.WriteAllText(file, "not a directory");

        var ex = Assert.Throws<PinsException>(() => PinsFile.Save(Path.Combine(file, "pins.json"), PinsDocument.Empty));

        Assert.Contains("Could not write", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Save_ThatCannotReplaceTheFile_LeavesNoTemporaryFileBehind()
    {
        // A directory where the file should go: the write succeeds, the rename cannot.
        var target = PathIn("pins.json");
        Directory.CreateDirectory(target);

        Assert.Throws<PinsException>(() => PinsFile.Save(target, PinsDocument.Empty));

        Assert.Equal([target], Directory.GetFileSystemEntries(_directory));
    }

    [Fact]
    public void Save_RejectsNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => PinsFile.Save(null!, PinsDocument.Empty));
        Assert.Throws<ArgumentNullException>(() => PinsFile.Save("p", null!));
    }

    // --------------------------------------------------------- compression

    [Fact]
    public void Compress_RoundTrips()
    {
        const string canonical = """{"description":"Reads a file. é ✓","name":"read"}""";

        var compressed = PinsFile.Compress(canonical);

        Assert.Equal(canonical, PinsFile.Decompress(compressed));
        Assert.DoesNotContain("Reads", compressed, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("not base64!")]
    [InlineData("/////w==")]
    public void Decompress_OfSomethingElse_Throws(string value)
    {
        Assert.Throws<PinsException>(() => PinsFile.Decompress(value));
    }

    [Fact]
    public void Compression_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => PinsFile.Compress(null!));
        Assert.Throws<ArgumentNullException>(() => PinsFile.Decompress(null!));
    }
}
