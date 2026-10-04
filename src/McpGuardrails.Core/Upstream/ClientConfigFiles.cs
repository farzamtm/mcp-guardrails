using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace McpGuardrails.Core.Upstream;

/// <summary>
/// The disk side of <c>wrap</c> and <c>unwrap</c>: backups, atomic replacement
/// and the "has anyone touched this since?" check.
/// </summary>
/// <remarks>
/// The rules, all in service of never losing a user's client config:
///
/// - <b>The backup is written and flushed to disk before the config is
///   touched,</b> and it holds the original bytes exactly, so a plain
///   <c>cp</c> restores it even without this tool.
/// - <b>Files are replaced atomically:</b> written to a temporary file in the same
///   directory, flushed, then renamed over the target. A crash leaves the old
///   file or the new one, never half of each.
/// - <b><c>unwrap</c> refuses when the config changed after <c>wrap</c></b>
///   (a server added in the client's UI, say), because restoring the backup
///   would silently throw that change away. A hash of what <c>wrap</c> wrote,
///   kept beside the backup, is how it knows.
/// </remarks>
public static class ClientConfigFiles
{
    /// <summary>What a backup's file name starts with, after the config's own name.</summary>
    public const string BackupMarker = ".guardrails-backup-";

    /// <summary>The suffix of the file holding the hash of the wrapped config.</summary>
    public const string HashSuffix = ".sha256";

    /// <summary>
    /// Writes the backup and the servers file, then replaces the client config.
    /// </summary>
    /// <param name="configPath">The client config to replace.</param>
    /// <param name="originalBytes">Its current contents, exactly as read.</param>
    /// <param name="wrappedText">What it becomes.</param>
    /// <param name="serversPath">Where the servers file goes.</param>
    /// <param name="serversText">The servers file.</param>
    /// <param name="now">For the backup's name.</param>
    /// <returns>The backup's path.</returns>
    /// <exception cref="ClientConfigException">The servers file already exists, or a backup by that name does.</exception>
    public static string ApplyWrap(
        string configPath,
        byte[] originalBytes,
        string wrappedText,
        string serversPath,
        string serversText,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(configPath);
        ArgumentNullException.ThrowIfNull(originalBytes);
        ArgumentNullException.ThrowIfNull(wrappedText);
        ArgumentNullException.ThrowIfNull(serversPath);
        ArgumentNullException.ThrowIfNull(serversText);

        // Someone's existing servers file is configuration in its own right;
        // overwriting it to wrap a second client would lose the first.
        if (File.Exists(serversPath))
        {
            throw new ClientConfigException(
                $"Servers file '{serversPath}' already exists. Choose another with '-o <path>', " +
                "or merge the servers into it by hand.");
        }

        var backupPath = configPath + BackupMarker + now.UtcDateTime.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);
        var wrappedBytes = Encoding.UTF8.GetBytes(wrappedText);

        try
        {
            WriteDurably(backupPath, originalBytes, FileMode.CreateNew);
        }
        catch (IOException) when (File.Exists(backupPath))
        {
            throw new ClientConfigException($"Backup '{backupPath}' already exists. Wait a second and try again.");
        }

        WriteDurably(backupPath + HashSuffix, Encoding.ASCII.GetBytes(Hash(wrappedBytes)), FileMode.CreateNew);

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(serversPath))!);
        ReplaceAtomically(serversPath, Encoding.UTF8.GetBytes(serversText));
        ReplaceAtomically(configPath, wrappedBytes);

        return backupPath;
    }

    /// <summary>The newest backup of <paramref name="configPath"/>, or null when there is none.</summary>
    /// <remarks>The timestamp in the name sorts, so the last name in ordinal order is the newest.</remarks>
    public static string? FindLatestBackup(string configPath)
    {
        ArgumentNullException.ThrowIfNull(configPath);

        var directory = Path.GetDirectoryName(Path.GetFullPath(configPath))!;
        if (!Directory.Exists(directory))
        {
            return null;
        }

        var prefix = Path.GetFileName(configPath) + BackupMarker;

        return Directory.EnumerateFiles(directory, prefix + "*")
            .Where(path => !path.EndsWith(HashSuffix, StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .LastOrDefault();
    }

    /// <summary>
    /// Puts the newest backup back in place of the client config, byte for byte.
    /// </summary>
    /// <param name="configPath">The wrapped client config.</param>
    /// <param name="force">Restore even if the config changed after it was wrapped.</param>
    /// <returns>The backup that was restored.</returns>
    /// <exception cref="ClientConfigException">
    /// There is no backup, or the config changed since <c>wrap</c> and
    /// <paramref name="force"/> is false.
    /// </exception>
    public static string Restore(string configPath, bool force)
    {
        ArgumentNullException.ThrowIfNull(configPath);

        var backupPath = FindLatestBackup(configPath)
                         ?? throw new ClientConfigException($"No backup of '{configPath}' was found, so there is nothing to restore.");

        if (!force)
        {
            var expected = File.Exists(backupPath + HashSuffix)
                ? File.ReadAllText(backupPath + HashSuffix).Trim()
                : null;
            var actual = File.Exists(configPath) ? Hash(File.ReadAllBytes(configPath)) : null;

            if (expected is null || !string.Equals(expected, actual, StringComparison.Ordinal))
            {
                throw new ClientConfigException(
                    $"'{configPath}' changed after it was wrapped, so restoring '{backupPath}' would lose that " +
                    "change. Look at both files, then run again with --force to restore the backup anyway.");
            }
        }

        ReplaceAtomically(configPath, File.ReadAllBytes(backupPath));

        // The original is back in place; leaving the backup would make the next
        // unwrap restore it again over whatever comes after.
        File.Delete(backupPath + HashSuffix);
        File.Delete(backupPath);

        return backupPath;
    }

    /// <summary>Hex SHA-256, as stored beside a backup.</summary>
    internal static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static void WriteDurably(string path, byte[] bytes, FileMode mode)
    {
        using var stream = new FileStream(path, mode, FileAccess.Write, FileShare.None);
        stream.Write(bytes);

        // Flush(true) asks the OS to put it on the disk, not just in its cache:
        // the backup has to survive a power cut that happens after the rename.
        stream.Flush(flushToDisk: true);
    }

    private static void ReplaceAtomically(string path, byte[] bytes)
    {
        var temporary = $"{path}.guardrails-tmp-{Guid.NewGuid():N}";
        try
        {
            WriteDurably(temporary, bytes, FileMode.CreateNew);
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            // Only still there if the move failed.
            File.Delete(temporary);
        }
    }
}
