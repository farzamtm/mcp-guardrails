using System.Text;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Tests.Upstream;

/// <summary>
/// The disk side of wrap and unwrap, against real files in a temporary directory:
/// the promises here are about bytes on disk.
/// </summary>
public sealed class ClientConfigFilesTests : IDisposable
{
    private static readonly DateTimeOffset _now = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);

    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), $"guardrails-wrap-{Guid.NewGuid():N}");

    private readonly byte[] _original =
        [.. Encoding.UTF8.GetBytes("{\r\n  \"mcpServers\": { \"fs\": {} }\r\n}"), 0x20];

    public ClientConfigFilesTests()
    {
        Directory.CreateDirectory(_directory);
        File.WriteAllBytes(Config, _original);
    }

    private string Config => Path.Combine(_directory, "claude_desktop_config.json");

    private string Servers => Path.Combine(_directory, "nested", "servers.yaml");

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private string Wrap(DateTimeOffset? at = null) =>
        ClientConfigFiles.ApplyWrap(Config, _original, "{ \"wrapped\": true }\n", Servers, "version: 1\n", at ?? _now);

    [Fact]
    public void WrapThenUnwrap_RestoresTheOriginalByteForByte()
    {
        var backup = Wrap();

        Assert.Equal(Config + ".guardrails-backup-20261004120000", backup);
        Assert.Equal(_original, File.ReadAllBytes(backup));
        Assert.Equal("{ \"wrapped\": true }\n", File.ReadAllText(Config));
        Assert.Equal("version: 1\n", File.ReadAllText(Servers));
        Assert.Empty(Directory.GetFiles(_directory, "*guardrails-tmp*"));

        Assert.Equal(backup, ClientConfigFiles.Restore(Config, force: false));

        Assert.Equal(_original, File.ReadAllBytes(Config));
        Assert.False(File.Exists(backup));
        Assert.False(File.Exists(backup + ClientConfigFiles.HashSuffix));
    }

    [Fact]
    public void Unwrap_RefusesWhenTheConfigChangedSinceWrap()
    {
        Wrap();
        File.AppendAllText(Config, "// a server added in the client's UI\n");

        var exception = Assert.Throws<ClientConfigException>(() => ClientConfigFiles.Restore(Config, force: false));
        Assert.Contains("changed after it was wrapped", exception.Message, StringComparison.Ordinal);
        Assert.Contains("--force", exception.Message, StringComparison.Ordinal);

        // --force restores anyway.
        ClientConfigFiles.Restore(Config, force: true);
        Assert.Equal(_original, File.ReadAllBytes(Config));
    }

    [Fact]
    public void Unwrap_RefusesWithoutTheHashFileOrTheConfig()
    {
        var backup = Wrap();
        File.Delete(backup + ClientConfigFiles.HashSuffix);
        Assert.Throws<ClientConfigException>(() => ClientConfigFiles.Restore(Config, force: false));

        File.WriteAllText(backup + ClientConfigFiles.HashSuffix, "abc");
        File.Delete(Config);
        Assert.Throws<ClientConfigException>(() => ClientConfigFiles.Restore(Config, force: false));
    }

    [Fact]
    public void Unwrap_RestoresTheNewestBackup()
    {
        Wrap();
        File.Delete(Servers);
        File.WriteAllText(Config, "second original");
        ClientConfigFiles.ApplyWrap(Config, Encoding.UTF8.GetBytes("second original"), "{}", Servers, "v", _now.AddDays(1));

        ClientConfigFiles.Restore(Config, force: false);

        Assert.Equal("second original", File.ReadAllText(Config));
        Assert.EndsWith("20261004120000", ClientConfigFiles.FindLatestBackup(Config), StringComparison.Ordinal);
    }

    [Fact]
    public void Unwrap_RefusesWhenThereIsNoBackup() =>
        Assert.Contains(
            "No backup",
            Assert.Throws<ClientConfigException>(() => ClientConfigFiles.Restore(Config, force: false)).Message,
            StringComparison.Ordinal);

    [Fact]
    public void FindLatestBackup_ToleratesAMissingDirectory() =>
        Assert.Null(ClientConfigFiles.FindLatestBackup(Path.Combine(_directory, "nope", "config.json")));

    [Fact]
    public void Wrap_RefusesToOverwriteAnExistingServersFile()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Servers)!);
        File.WriteAllText(Servers, "someone's servers");

        Assert.Contains("already exists", Assert.Throws<ClientConfigException>(() => Wrap()).Message, StringComparison.Ordinal);

        // Nothing was touched.
        Assert.Equal(_original, File.ReadAllBytes(Config));
        Assert.Null(ClientConfigFiles.FindLatestBackup(Config));
    }

    [Fact]
    public void Wrap_RefusesToOverwriteABackupFromTheSameSecond()
    {
        Wrap();
        File.Delete(Servers);

        Assert.Contains("Backup", Assert.Throws<ClientConfigException>(() => Wrap()).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Wrap_LeavesNoTemporaryFileWhenTheReplaceFails()
    {
        // The target is a directory, so the final rename fails after the
        // temporary file was written; it must not be left behind.
        var blocked = Path.Combine(_directory, "blocked");
        Directory.CreateDirectory(blocked);

        Assert.ThrowsAny<Exception>(() =>
            ClientConfigFiles.ApplyWrap(Config, _original, "{}", blocked, "v", _now));
        Assert.Empty(Directory.GetFiles(_directory, "*guardrails-tmp*"));
    }

    [Fact]
    public void RejectsNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => ClientConfigFiles.ApplyWrap(null!, [], "", "s", "", _now));
        Assert.Throws<ArgumentNullException>(() => ClientConfigFiles.ApplyWrap("c", null!, "", "s", "", _now));
        Assert.Throws<ArgumentNullException>(() => ClientConfigFiles.ApplyWrap("c", [], null!, "s", "", _now));
        Assert.Throws<ArgumentNullException>(() => ClientConfigFiles.ApplyWrap("c", [], "", null!, "", _now));
        Assert.Throws<ArgumentNullException>(() => ClientConfigFiles.ApplyWrap("c", [], "", "s", null!, _now));
        Assert.Throws<ArgumentNullException>(() => ClientConfigFiles.FindLatestBackup(null!));
        Assert.Throws<ArgumentNullException>(() => ClientConfigFiles.Restore(null!, force: false));
    }
}
