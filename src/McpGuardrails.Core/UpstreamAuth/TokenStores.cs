using System.Text;

namespace McpGuardrails.Core.UpstreamAuth;

/// <summary>A credential store that could not read, write or delete.</summary>
public sealed class TokenStoreException(string message) : Exception(message);

/// <summary>
/// Where a remote server's OAuth tokens are kept between runs, one secret per
/// server name.
/// </summary>
/// <remarks>
/// Never the servers file and never the audit log: the servers file gets
/// committed and pasted into issues, and a refresh token is a long-lived
/// credential.
/// </remarks>
public interface ITokenStore
{
    /// <summary>What and where the store is, for <c>auth status</c> and log lines.</summary>
    string Description { get; }

    /// <summary>The secret stored for <paramref name="server"/>, or null when there is none.</summary>
    /// <exception cref="TokenStoreException">The store could not be read.</exception>
    string? Read(string server);

    /// <summary>Stores <paramref name="secret"/> for <paramref name="server"/>, replacing any.</summary>
    /// <exception cref="TokenStoreException">The store could not be written.</exception>
    void Write(string server, string secret);

    /// <summary>Removes what is stored for <paramref name="server"/>.</summary>
    /// <returns>False when there was nothing to remove.</returns>
    /// <exception cref="TokenStoreException">The store could not be changed.</exception>
    bool Delete(string server);
}

/// <summary>What a finished process said.</summary>
public sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError);

/// <summary>
/// Runs a program to completion. A program that cannot be started answers exit
/// code 127, the shell's "command not found", rather than throwing.
/// </summary>
/// <param name="fileName">The program, found on PATH.</param>
/// <param name="arguments">Its arguments, passed as an argument list, never through a shell.</param>
/// <param name="standardInput">Written to its stdin, then closed; null for none.</param>
public delegate ProcessResult ProcessRunner(string fileName, IReadOnlyList<string> arguments, string? standardInput);

/// <summary>
/// The macOS login keychain, through the <c>security</c> tool that ships with
/// the OS.
/// </summary>
/// <remarks>
/// The secret is written through <c>security -i</c>, which reads its command
/// from stdin, because on the command line it would be visible to every process
/// on the machine through <c>ps</c>. It is hex-encoded so no quoting rule of
/// that command language can be broken by what a token contains.
/// </remarks>
public sealed class KeychainTokenStore(ProcessRunner run, string service = KeychainTokenStore.DefaultService) : ITokenStore
{
    /// <summary>The keychain service name the items are filed under.</summary>
    public const string DefaultService = "mcp-guardrails";

    // What `security` exits with when the item does not exist.
    private const int _notFound = 44;

    public string Description => "the macOS Keychain";

    public string? Read(string server)
    {
        var result = run("security", ["find-generic-password", "-a", server, "-s", service, "-w"], null);

        return result.ExitCode switch
        {
            0 => Hex.Decode(result.StandardOutput.Trim()),
            _notFound => null,
            _ => throw Failed("read", result),
        };
    }

    public void Write(string server, string secret)
    {
        var result = run(
            "security",
            ["-i"],
            $"add-generic-password -U -a {server} -s {service} -w {Hex.Encode(secret)}\n");

        if (result.ExitCode != 0)
        {
            throw Failed("write", result);
        }
    }

    public bool Delete(string server)
    {
        var result = run("security", ["delete-generic-password", "-a", server, "-s", service], null);

        return result.ExitCode switch
        {
            0 => true,
            _notFound => false,
            _ => throw Failed("delete", result),
        };
    }

    private static TokenStoreException Failed(string what, ProcessResult result) =>
        new($"Cannot {what} the macOS Keychain: security exited {result.ExitCode} ({result.StandardError.Trim()}).");
}

/// <summary>
/// The freedesktop Secret Service (GNOME Keyring, KWallet), through
/// <c>secret-tool</c> from libsecret.
/// </summary>
/// <remarks>
/// <c>secret-tool store</c> reads the secret from stdin, so it never appears on a
/// command line.
/// </remarks>
public sealed class SecretServiceTokenStore(ProcessRunner run, string service = KeychainTokenStore.DefaultService) : ITokenStore
{
    public string Description => "the Secret Service (secret-tool)";

    /// <summary>
    /// True when <c>secret-tool</c> is installed and a keyring answers. On a
    /// headless machine with no D-Bus session it is installed and fails with a
    /// message, which is what tells the two cases apart.
    /// </summary>
    public static bool IsAvailable(ProcessRunner run)
    {
        ArgumentNullException.ThrowIfNull(run);

        var result = run("secret-tool", ["lookup", "service", KeychainTokenStore.DefaultService, "account", "-availability-probe-"], null);
        return result.ExitCode == 0 || (result.ExitCode == 1 && result.StandardError.Trim().Length == 0);
    }

    public string? Read(string server)
    {
        var result = run("secret-tool", ["lookup", "service", service, "account", server], null);

        if (result.ExitCode == 0)
        {
            return result.StandardOutput;
        }

        // secret-tool exits 1, silently, for an item that is not there.
        return result.ExitCode == 1 && result.StandardError.Trim().Length == 0
            ? null
            : throw Failed("read", result);
    }

    public void Write(string server, string secret)
    {
        var result = run(
            "secret-tool",
            ["store", "--label", $"mcp-guardrails: {server}", "service", service, "account", server],
            secret);

        if (result.ExitCode != 0)
        {
            throw Failed("write", result);
        }
    }

    public bool Delete(string server)
    {
        // clear reports nothing about whether there was an item, so look first.
        var existed = Read(server) is not null;
        var result = run("secret-tool", ["clear", "service", service, "account", server], null);

        return result.ExitCode == 0 ? existed : throw Failed("delete", result);
    }

    private static TokenStoreException Failed(string what, ProcessResult result) =>
        new($"Cannot {what} the Secret Service: secret-tool exited {result.ExitCode} ({result.StandardError.Trim()}).");
}

/// <summary>Encrypts and decrypts what a <see cref="FileTokenStore"/> writes.</summary>
/// <remarks>On Windows, DPAPI: the files can then only be read by the same user on the same machine.</remarks>
public interface ISecretProtector
{
    string Name { get; }

    byte[] Protect(byte[] data);

    byte[] Unprotect(byte[] data);
}

/// <summary>
/// One file per server in a directory only the user can read: DPAPI-encrypted
/// on Windows, and the fallback where no OS credential store is available.
/// </summary>
/// <remarks>
/// Written to a temporary file and renamed over the old one, so a crash
/// mid-write leaves the previous tokens rather than half a file. On Unix the
/// directory is created 0700 and each file 0600 from the start, never widened
/// and then narrowed.
/// </remarks>
/// <param name="directory">Where the files go.</param>
/// <param name="unixPermissions">Create with owner-only Unix permissions; false on Windows.</param>
/// <param name="protector">Encryption for the file contents, or null for none.</param>
public sealed class FileTokenStore(string directory, bool unixPermissions, ISecretProtector? protector = null) : ITokenStore
{
    private const UnixFileMode _ownerOnlyDirectory =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    private const UnixFileMode _ownerOnlyFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    public string Description => protector is null
        ? $"files readable only by you in {directory}"
        : $"{protector.Name}-encrypted files in {directory}";

    public string? Read(string server)
    {
        var path = PathFor(server);

        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            var bytes = File.ReadAllBytes(path);
            return Encoding.UTF8.GetString(protector?.Unprotect(bytes) ?? bytes);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new TokenStoreException($"Cannot read '{path}': {ex.Message}");
        }
    }

    public void Write(string server, string secret)
    {
        var path = PathFor(server);
        var temporary = $"{path}.{Guid.NewGuid():N}.tmp";

        // CA1416: the Unix-mode APIs throw on Windows, and the caller asks for
        // them only elsewhere - the platform is the CLI's decision, made once,
        // rather than an OS check here whose other branch no test run can reach.
#pragma warning disable CA1416
        try
        {
            if (unixPermissions)
            {
                Directory.CreateDirectory(directory, _ownerOnlyDirectory);
            }
            else
            {
                Directory.CreateDirectory(directory);
            }

            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
            if (unixPermissions)
            {
                options.UnixCreateMode = _ownerOnlyFile;
            }

            var bytes = Encoding.UTF8.GetBytes(secret);
            using (var stream = new FileStream(temporary, options))
            {
                stream.Write(protector?.Protect(bytes) ?? bytes);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Exists first: Delete throws when the directory itself is missing.
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }

            throw new TokenStoreException($"Cannot write '{path}': {ex.Message}");
        }
#pragma warning restore CA1416
    }

    public bool Delete(string server)
    {
        var path = PathFor(server);

        try
        {
            if (!File.Exists(path))
            {
                return false;
            }

            File.Delete(path);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new TokenStoreException($"Cannot delete '{path}': {ex.Message}");
        }
    }

    // Server names are letters, digits and hyphens, so the name is a safe file name.
    private string PathFor(string server) => Path.Combine(directory, $"{server}.json");
}

/// <summary>Which credential store holds the tokens.</summary>
public enum TokenStoreKind
{
    Keychain,
    SecretService,
    Dpapi,
    File,
}

/// <summary>Chooses the credential store for this machine.</summary>
public static class TokenStoreSelection
{
    /// <summary>The environment variable that overrides the choice.</summary>
    public const string Variable = "GUARDRAILS_TOKEN_STORE";

    /// <summary>
    /// The OS store where there is one; a file store, with a warning, where there
    /// is not.
    /// </summary>
    /// <param name="requested">The value of <see cref="Variable"/>, or null.</param>
    /// <param name="isMacOS">True on macOS.</param>
    /// <param name="isWindows">True on Windows.</param>
    /// <param name="secretServiceAvailable">Asked only on Linux and other Unix systems.</param>
    /// <exception cref="TokenStoreException">The variable names no store.</exception>
    public static (TokenStoreKind Kind, string? Warning) Choose(
        string? requested, bool isMacOS, bool isWindows, Func<bool> secretServiceAvailable)
    {
        ArgumentNullException.ThrowIfNull(secretServiceAvailable);

        const string fileWarning =
            "OAuth tokens are stored in files only your user can read, not in an OS credential store. " +
            "Anyone who can read your home directory as you can use them.";

        switch (requested)
        {
            case "keychain":
                return (TokenStoreKind.Keychain, null);
            case "secret-service":
                return (TokenStoreKind.SecretService, null);
            case "dpapi":
                return (TokenStoreKind.Dpapi, null);
            case "file":
                return (TokenStoreKind.File, fileWarning);
            case not null:
                throw new TokenStoreException(
                    $"{Variable} is '{requested}'. Use keychain, secret-service, dpapi or file.");
        }

        if (isMacOS)
        {
            return (TokenStoreKind.Keychain, null);
        }

        if (isWindows)
        {
            return (TokenStoreKind.Dpapi, null);
        }

        return secretServiceAvailable()
            ? (TokenStoreKind.SecretService, null)
            : (TokenStoreKind.File, "No Secret Service was found (install libsecret's secret-tool and run a keyring). " + fileWarning);
    }
}

internal static class Hex
{
    public static string Encode(string text) => Convert.ToHexString(Encoding.UTF8.GetBytes(text));

    /// <exception cref="TokenStoreException">The stored value is not hex.</exception>
    public static string Decode(string hex)
    {
        try
        {
            return Encoding.UTF8.GetString(Convert.FromHexString(hex));
        }
        catch (FormatException)
        {
            throw new TokenStoreException("The keychain item is not one this proxy wrote.");
        }
    }
}
