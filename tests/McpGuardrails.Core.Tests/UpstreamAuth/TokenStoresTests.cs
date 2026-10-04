using System.Text;
using McpGuardrails.Core.UpstreamAuth;

namespace McpGuardrails.Core.Tests.UpstreamAuth;

/// <summary>
/// The credential stores against a fake process runner, and the file store
/// against a real temporary directory.
/// </summary>
public sealed class TokenStoresTests
{
    /// <summary>Answers each call from a script and keeps what it was asked.</summary>
    private sealed class FakeRunner(params ProcessResult[] answers)
    {
        private readonly Queue<ProcessResult> _answers = new(answers);

        public List<(string File, IReadOnlyList<string> Args, string? Input)> Calls { get; } = [];

        public ProcessResult Run(string file, IReadOnlyList<string> args, string? input)
        {
            Calls.Add((file, args, input));
            return _answers.Dequeue();
        }
    }

    private static ProcessResult Ok(string output = "") => new(0, output, string.Empty);

    private static ProcessResult Exit(int code, string error = "") => new(code, string.Empty, error);

    // ------------------------------------------------------------ keychain

    /// <summary>
    /// A stand-in for <c>security</c> that keeps items in a dictionary, so
    /// the write-then-read-back path runs end to end. <paramref name="lineLimit"/>
    /// models an interactive line buffer that cuts long commands short.
    /// </summary>
    private sealed class FakeKeychain(int lineLimit = int.MaxValue)
    {
        private readonly Dictionary<string, string> _items = new(StringComparer.Ordinal);

        public ProcessResult Run(string file, IReadOnlyList<string> args, string? input)
        {
            if (args is ["-i"])
            {
                var line = input![..Math.Min(input!.Length, lineLimit)].TrimEnd('\n');
                var parts = line.Split(' ');
                _items[parts[3]] = parts[^1];
                return Ok();
            }

            return _items.TryGetValue(args[2], out var hex) ? Ok(hex + "\n") : Exit(44);
        }
    }

    [Fact]
    public void Keychain_WritesTheSecretThroughStdin_NeverOnTheCommandLine()
    {
        const string secret = "{\"access_token\":\"secret value\"}";
        var runner = new FakeRunner(Ok(), Ok(Convert.ToHexString(Encoding.UTF8.GetBytes(secret)) + "\n"));
        var store = new KeychainTokenStore(runner.Run);

        store.Write("linear", secret);

        Assert.Equal(2, runner.Calls.Count);
        var (file, args, input) = runner.Calls[0];
        Assert.Equal("security", file);
        Assert.Equal(["-i"], args);
        Assert.DoesNotContain("secret", string.Join(' ', args), StringComparison.Ordinal);
        Assert.StartsWith("add-generic-password -U -a linear -s mcp-guardrails -w ", input, StringComparison.Ordinal);
        Assert.DoesNotContain("secret value", input, StringComparison.Ordinal);
        Assert.Equal("the macOS Keychain", store.Description);
    }

    [Fact]
    public void Keychain_RoundTripsALargeLogin()
    {
        // About what two provider JWTs and a client registration come to. The
        // real `security -i` line limit was not measured; this pins only that
        // the write path itself does not cut a large secret short.
        var secret = new string('x', 6 * 1024);
        var store = new KeychainTokenStore(new FakeKeychain().Run);

        store.Write("linear", secret);

        Assert.Equal(secret, store.Read("linear"));
    }

    [Fact]
    public void Keychain_ThatStoresALoginShortened_FailsTheWriteLoudly()
    {
        var store = new KeychainTokenStore(new FakeKeychain(lineLimit: 4096).Run);

        var ex = Assert.Throws<TokenStoreException>(() => store.Write("linear", new string('x', 6 * 1024)));
        Assert.Contains("did not store", ex.Message, StringComparison.Ordinal);
        Assert.Contains("GUARDRAILS_TOKEN_STORE=file", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Keychain_ThatCannotReadBackWhatItWrote_FailsTheWrite()
    {
        var store = new KeychainTokenStore(new FakeRunner(Ok(), Exit(51, "locked")).Run);

        Assert.Throws<TokenStoreException>(() => store.Write("linear", "secret"));
    }

    [Fact]
    public void Keychain_ReadsBackWhatItWrote()
    {
        var hex = Convert.ToHexString(Encoding.UTF8.GetBytes("{\"a\":\"ü\"}"));
        var runner = new FakeRunner(Ok(hex + "\n"));

        Assert.Equal("{\"a\":\"ü\"}", new KeychainTokenStore(runner.Run, "svc").Read("linear"));
        Assert.Equal(["find-generic-password", "-a", "linear", "-s", "svc", "-w"], runner.Calls[0].Args);
    }

    [Fact]
    public void Keychain_NotFound_IsNull_AndOtherFailuresThrow()
    {
        Assert.Null(new KeychainTokenStore(new FakeRunner(Exit(44)).Run).Read("x"));

        var ex = Assert.Throws<TokenStoreException>(
            () => new KeychainTokenStore(new FakeRunner(Exit(51, "locked")).Run).Read("x"));
        Assert.Contains("security exited 51 (locked)", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Keychain_AnItemThatIsNotHex_IsRefused()
    {
        var ex = Assert.Throws<TokenStoreException>(
            () => new KeychainTokenStore(new FakeRunner(Ok("not hex")).Run).Read("x"));
        Assert.Contains("not one this proxy wrote", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Keychain_AFailedWrite_Throws()
    {
        Assert.Throws<TokenStoreException>(
            () => new KeychainTokenStore(new FakeRunner(Exit(1, "denied")).Run).Write("x", "y"));
    }

    [Fact]
    public void Keychain_Delete_ReportsWhetherThereWasAnything()
    {
        Assert.True(new KeychainTokenStore(new FakeRunner(Ok()).Run).Delete("x"));
        Assert.False(new KeychainTokenStore(new FakeRunner(Exit(44)).Run).Delete("x"));
        Assert.Throws<TokenStoreException>(() => new KeychainTokenStore(new FakeRunner(Exit(2)).Run).Delete("x"));
    }

    // ------------------------------------------------------ secret service

    [Fact]
    public void SecretService_StoresThroughStdin()
    {
        var runner = new FakeRunner(Ok());

        new SecretServiceTokenStore(runner.Run).Write("linear", "the secret");

        var (file, args, input) = Assert.Single(runner.Calls);
        Assert.Equal("secret-tool", file);
        Assert.Equal(["store", "--label", "mcp-guardrails: linear", "service", "mcp-guardrails", "account", "linear"], args);
        Assert.Equal("the secret", input);
    }

    [Fact]
    public void SecretService_Reads_AndTellsMissingFromBroken()
    {
        Assert.Equal("s", new SecretServiceTokenStore(new FakeRunner(Ok("s")).Run).Read("x"));
        Assert.Null(new SecretServiceTokenStore(new FakeRunner(Exit(1)).Run).Read("x"));

        var ex = Assert.Throws<TokenStoreException>(
            () => new SecretServiceTokenStore(new FakeRunner(Exit(1, "Cannot autolaunch D-Bus")).Run).Read("x"));
        Assert.Contains("Cannot autolaunch D-Bus", ex.Message, StringComparison.Ordinal);
        Assert.Equal("the Secret Service (secret-tool)", new SecretServiceTokenStore(new FakeRunner().Run).Description);
    }

    [Fact]
    public void SecretService_AFailedWrite_Throws()
    {
        Assert.Throws<TokenStoreException>(
            () => new SecretServiceTokenStore(new FakeRunner(Exit(1, "no keyring")).Run).Write("x", "y"));
    }

    [Fact]
    public void SecretService_Delete_LooksFirst()
    {
        Assert.True(new SecretServiceTokenStore(new FakeRunner(Ok("s"), Ok()).Run).Delete("x"));
        Assert.False(new SecretServiceTokenStore(new FakeRunner(Exit(1), Ok()).Run).Delete("x"));
        Assert.Throws<TokenStoreException>(
            () => new SecretServiceTokenStore(new FakeRunner(Exit(1), Exit(3, "broken")).Run).Delete("x"));
    }

    [Theory]
    [InlineData(0, "", true)]
    [InlineData(1, "", true)]
    [InlineData(1, "Cannot autolaunch D-Bus without X11", false)]
    [InlineData(127, "not found", false)]
    public void SecretService_IsAvailable_OnlyWhenAKeyringAnswers(int exit, string error, bool expected)
    {
        Assert.Equal(expected, SecretServiceTokenStore.IsAvailable(new FakeRunner(new ProcessResult(exit, string.Empty, error)).Run));
        Assert.Throws<ArgumentNullException>(() => SecretServiceTokenStore.IsAvailable(null!));
    }

    // ---------------------------------------------------------------- file

    private sealed class Reverser : ISecretProtector
    {
        public string Name => "test";

        public byte[] Protect(byte[] data) => [.. data.Reverse()];

        public byte[] Unprotect(byte[] data) => [.. data.Reverse()];
    }

    private static string TempDirectory() =>
        Path.Combine(Path.GetTempPath(), $"guardrails-tokens-{Guid.NewGuid():N}", "tokens");

    [Fact]
    public void File_RoundTrips_AndOverwrites()
    {
        var store = new FileTokenStore(TempDirectory(), unixPermissions: !OperatingSystem.IsWindows());

        Assert.Null(store.Read("linear"));
        store.Write("linear", "one");
        store.Write("linear", "two");

        Assert.Equal("two", store.Read("linear"));
    }

    [Fact]
    public void File_DescribesWhatProtectsIt()
    {
        // On Windows without DPAPI there is no owner-only mode to set, so the
        // description does not promise one.
        Assert.Equal("files readable only by you in /t", new FileTokenStore("/t", unixPermissions: true).Description);
        Assert.Equal(
            "unencrypted files in C:\\t, protected only by that folder's permissions",
            new FileTokenStore("C:\\t", unixPermissions: false).Description);
    }

    [Fact]
    public void File_IsOwnerOnly_OnUnix()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var directory = TempDirectory();
        new FileTokenStore(directory, unixPermissions: true).Write("linear", "secret");

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(directory, "linear.json")));
        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
            File.GetUnixFileMode(directory));
        Assert.Empty(Directory.GetFiles(directory, "*.tmp"));
    }

    [Fact]
    public void File_WithoutUnixPermissions_StillWorks()
    {
        var store = new FileTokenStore(TempDirectory(), unixPermissions: false);

        store.Write("linear", "secret");

        Assert.Equal("secret", store.Read("linear"));
    }

    [Fact]
    public void File_AppliesTheProtector()
    {
        var directory = TempDirectory();
        var store = new FileTokenStore(directory, unixPermissions: false, new Reverser());

        store.Write("linear", "abc");

        Assert.Equal("cba", File.ReadAllText(Path.Combine(directory, "linear.json")));
        Assert.Equal("abc", store.Read("linear"));
        Assert.StartsWith("test-encrypted files in", store.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void File_Delete_ReportsWhetherThereWasAnything()
    {
        var store = new FileTokenStore(TempDirectory(), unixPermissions: false);
        store.Write("linear", "x");

        Assert.True(store.Delete("linear"));
        Assert.False(store.Delete("linear"));
        Assert.Null(store.Read("linear"));
    }

    [Fact]
    public void File_AnUnreadableEntry_Throws()
    {
        var directory = TempDirectory();
        Directory.CreateDirectory(Path.Combine(directory, "linear.json"));
        var store = new FileTokenStore(directory, unixPermissions: false);

        // A directory where the file should be: exists as neither, reads as an error.
        Assert.Null(store.Read("linear"));
        Assert.Throws<TokenStoreException>(() => store.Write("linear", "x"));
        Assert.Empty(Directory.GetFiles(directory, "*.tmp"));
    }

    [Fact]
    public void File_ADirectoryThatCannotBeCreated_IsAWriteError()
    {
        var parent = TempDirectory();
        Directory.CreateDirectory(Path.GetDirectoryName(parent)!);
        File.WriteAllText(parent, "a file where the directory should be");

        var ex = Assert.Throws<TokenStoreException>(
            () => new FileTokenStore(parent, unixPermissions: false).Write("linear", "x"));
        Assert.Contains("Cannot write", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void File_ReadAndDeleteErrors_AreStoreErrors()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var directory = TempDirectory();
        var store = new FileTokenStore(directory, unixPermissions: true);
        store.Write("linear", "x");
        File.SetUnixFileMode(Path.Combine(directory, "linear.json"), UnixFileMode.None);
        File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserExecute);

        try
        {
            Assert.Throws<TokenStoreException>(() => store.Read("linear"));
            Assert.Throws<TokenStoreException>(() => store.Delete("linear"));
        }
        finally
        {
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    // ----------------------------------------------------------- selection

    [Theory]
    [InlineData("keychain", true, false, TokenStoreKind.Keychain)]
    [InlineData("secret-service", false, false, TokenStoreKind.SecretService)]
    [InlineData("dpapi", false, true, TokenStoreKind.Dpapi)]
    public void AnExplicitStore_IsUsed_WithoutAWarning(string requested, bool isMacOS, bool isWindows, TokenStoreKind expected)
    {
        var (kind, warning) = TokenStoreSelection.Choose(requested, isMacOS, isWindows, () => throw new InvalidOperationException("not asked"));

        Assert.Equal(expected, kind);
        Assert.Null(warning);
    }

    [Theory]
    [InlineData("keychain", false, false, "macOS")]
    [InlineData("keychain", false, true, "macOS")]
    [InlineData("secret-service", true, false, "Linux")]
    [InlineData("secret-service", false, true, "Linux")]
    [InlineData("dpapi", true, false, "Windows")]
    [InlineData("dpapi", false, false, "Windows")]
    public void AnExplicitStoreThisPlatformLacks_IsRefusedAtOnce(string requested, bool isMacOS, bool isWindows, string platform)
    {
        // Otherwise it fails later, as "security exited 127".
        var ex = Assert.Throws<TokenStoreException>(
            () => TokenStoreSelection.Choose(requested, isMacOS, isWindows, () => true));

        Assert.Contains($"only available on {platform}", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnExplicitFileStore_IsUsed_WithAWarning()
    {
        var (kind, warning) = TokenStoreSelection.Choose("file", true, false, () => true);

        Assert.Equal(TokenStoreKind.File, kind);
        Assert.Contains("not in an OS credential store", warning, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnknownStore_IsRefused()
    {
        var ex = Assert.Throws<TokenStoreException>(() => TokenStoreSelection.Choose("vault", false, false, () => true));
        Assert.Contains("GUARDRAILS_TOKEN_STORE is 'vault'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheDefault_IsTheOsStore()
    {
        Assert.Equal(TokenStoreKind.Keychain, TokenStoreSelection.Choose(null, true, false, () => false).Kind);
        Assert.Equal(TokenStoreKind.Dpapi, TokenStoreSelection.Choose(null, false, true, () => false).Kind);
        Assert.Equal(TokenStoreKind.SecretService, TokenStoreSelection.Choose(null, false, false, () => true).Kind);
    }

    [Fact]
    public void WithoutASecretService_TheFallbackIsAFile_WithAWarning()
    {
        var (kind, warning) = TokenStoreSelection.Choose(null, false, false, () => false);

        Assert.Equal(TokenStoreKind.File, kind);
        Assert.Contains("No Secret Service was found", warning, StringComparison.Ordinal);
        Assert.Throws<ArgumentNullException>(() => TokenStoreSelection.Choose(null, false, false, null!));
    }
}
