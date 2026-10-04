using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using McpGuardrails.Cli.Commands;
using McpGuardrails.Core.UpstreamAuth;

namespace McpGuardrails.Cli;

/// <summary>
/// The credential store for remote servers' OAuth tokens on this machine.
/// </summary>
/// <remarks>
/// Only the platform plumbing lives here - running a program, calling DPAPI.
/// Which store to use and how each one is driven are decided in Core
/// (<see cref="TokenStoreSelection"/>, <see cref="KeychainTokenStore"/>,
/// <see cref="SecretServiceTokenStore"/>, <see cref="FileTokenStore"/>), where
/// they are unit-tested.
/// </remarks>
internal static class CliTokenStore
{
    /// <summary>The environment variable naming the file store's directory.</summary>
    public const string DirectoryVariable = "GUARDRAILS_TOKENS";

    /// <summary>Builds the store, and the warning to show when it is a plain file store.</summary>
    /// <exception cref="CommandFailedException"><see cref="TokenStoreSelection.Variable"/> names no store.</exception>
    public static (ITokenStore Store, string? Warning) Create()
    {
        (TokenStoreKind Kind, string? Warning) choice;
        try
        {
            choice = TokenStoreSelection.Choose(
                Environment.GetEnvironmentVariable(TokenStoreSelection.Variable),
                OperatingSystem.IsMacOS(),
                OperatingSystem.IsWindows(),
                () => SecretServiceTokenStore.IsAvailable(Run));
        }
        catch (TokenStoreException ex)
        {
            throw new CommandFailedException(2, ex.Message);
        }

        var directory = Environment.GetEnvironmentVariable(DirectoryVariable) ?? CliPaths.DefaultPath("tokens");

        ITokenStore store = choice.Kind switch
        {
            TokenStoreKind.Keychain => new KeychainTokenStore(Run),
            TokenStoreKind.SecretService => new SecretServiceTokenStore(Run),
            TokenStoreKind.Dpapi when OperatingSystem.IsWindows() =>
                new FileTokenStore(directory, unixPermissions: false, new DpapiProtector()),
            TokenStoreKind.Dpapi => throw new CommandFailedException(
                2, $"{TokenStoreSelection.Variable}=dpapi is only available on Windows."),
            _ => new FileTokenStore(directory, unixPermissions: !OperatingSystem.IsWindows()),
        };

        return (store, choice.Warning);
    }

    /// <summary>Runs a program to completion, never through a shell.</summary>
    private static ProcessResult Run(string fileName, IReadOnlyList<string> arguments, string? standardInput)
    {
        var start = new ProcessStartInfo(fileName)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        try
        {
            using var process = Process.Start(start)!;

            if (standardInput is not null)
            {
                process.StandardInput.Write(standardInput);
            }

            process.StandardInput.Close();

            // Both streams drained concurrently, so a chatty stderr cannot fill
            // its pipe and deadlock the read of stdout.
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            process.WaitForExit();

            return new ProcessResult(process.ExitCode, output.Result, error.Result);
        }
        catch (Win32Exception ex)
        {
            return new ProcessResult(127, string.Empty, ex.Message);
        }
    }

    /// <summary>DPAPI, current-user scope: readable only by this user on this machine.</summary>
    [SupportedOSPlatform("windows")]
    private sealed class DpapiProtector : ISecretProtector
    {
        public string Name => "DPAPI";

        public byte[] Protect(byte[] data) => Transform(data, protect: true);

        public byte[] Unprotect(byte[] data) => Transform(data, protect: false);

        private static byte[] Transform(byte[] data, bool protect)
        {
            var input = GCHandle.Alloc(data, GCHandleType.Pinned);
            try
            {
                var inBlob = new DataBlob { Size = data.Length, Data = input.AddrOfPinnedObject() };

                var succeeded = protect
                    ? CryptProtectData(ref inBlob, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, _uiForbidden, out var outBlob)
                    : CryptUnprotectData(ref inBlob, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, _uiForbidden, out outBlob);

                if (succeeded == 0)
                {
                    throw new TokenStoreException(
                        $"DPAPI could not {(protect ? "encrypt" : "decrypt")} the tokens (error {Marshal.GetLastWin32Error()}).");
                }

                try
                {
                    var result = new byte[outBlob.Size];
                    Marshal.Copy(outBlob.Data, result, 0, outBlob.Size);
                    return result;
                }
                finally
                {
                    LocalFree(outBlob.Data);
                }
            }
            finally
            {
                input.Free();
            }
        }

        // CRYPTPROTECT_UI_FORBIDDEN: never show a dialog; fail instead.
        private const int _uiForbidden = 0x1;

        [StructLayout(LayoutKind.Sequential)]
        private struct DataBlob
        {
            public int Size;
            public IntPtr Data;
        }

        // DllImport with blittable signatures (int for BOOL, IntPtr for pointers)
        // rather than LibraryImport, which would need unsafe code enabled for the
        // whole project; Native AOT compiles these stubs ahead of time either way.
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern int CryptProtectData(
            ref DataBlob dataIn, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob dataOut);

        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern int CryptUnprotectData(
            ref DataBlob dataIn, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob dataOut);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);
    }
}
