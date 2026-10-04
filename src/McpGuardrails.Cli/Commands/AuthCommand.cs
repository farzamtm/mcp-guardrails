using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using McpGuardrails.Core.Upstream;
using McpGuardrails.Core.UpstreamAuth;
using Microsoft.Extensions.Logging;
using ModelContextProtocol;
using ModelContextProtocol.Authentication;
using ModelContextProtocol.Client;

namespace McpGuardrails.Cli.Commands;

/// <summary>
/// <c>auth login|status|logout</c>: OAuth logins to remote servers.
/// </summary>
/// <remarks>
/// Logging in is a separate, interactive command because serving never is: the
/// proxy runs as a child of an MCP client, with no terminal and nowhere to show
/// a browser, so it only ever uses the tokens stored here and refreshes them.
/// Output goes to stdout - this command is not an MCP server.
/// </remarks>
internal sealed class AuthCommand : ICliCommand
{
    private const string _usage = "Usage: auth login <server> [--no-browser] | auth status | auth logout <server>";

    /// <summary>How long a login may take, from the URL being shown to the browser coming back.</summary>
    private static readonly TimeSpan _loginTimeout = TimeSpan.FromMinutes(5);

    public async Task<int> RunAsync(string[] args)
    {
        var operands = Operands(args);

        return operands switch
        {
            ["login", var server] => await LoginAsync(args, server),
            ["status"] => Status(args),
            ["logout", var server] => Logout(args, server),
            _ => throw new CommandFailedException(2, _usage),
        };
    }

    private static async Task<int> LoginAsync(string[] args, string name)
    {
        var config = OAuthServer(args, name);
        var (store, warning) = CliTokenStore.Create();
        if (warning is not null)
        {
            Console.Error.WriteLine($"warning: {warning}");
        }

        // The loopback listener is opened before anything is sent, so the port
        // is known for the redirect URI - and bound to 127.0.0.1 only, never to
        // an interface another machine could reach.
        using var listener = new TcpListener(IPAddress.Loopback, config.OAuth!.RedirectPort ?? 0);
        try
        {
            listener.Start();
        }
        catch (SocketException ex)
        {
            throw new CommandFailedException(1, $"Cannot listen on 127.0.0.1:{config.OAuth.RedirectPort} for the login redirect: {ex.Message}");
        }

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var redirect = new Uri($"http://127.0.0.1:{port}{LoopbackCallback.Path}");
        var openBrowser = !CliArgs.Has(args, "--no-browser");

        var options = UpstreamOAuth.ForLogin(config, store, redirect, async (context, cancellationToken) =>
        {
            Console.WriteLine($"To log in to '{name}', open this URL in a browser:");
            Console.WriteLine($"  {context.AuthorizationUri}");
            if (openBrowser)
            {
                OpenBrowser(context.AuthorizationUri);
            }

            return await WaitForCallbackAsync(listener, cancellationToken);
        });

        using var loggerFactory = LoggerFactory.Create(logging => CliLogging.ToStandardError(logging, listing: true));
        using var timeout = new CancellationTokenSource(_loginTimeout);

        try
        {
            await using var client = await McpClient.CreateAsync(
                UpstreamRegistry.CreateTransport(config, loggerFactory, options),
                loggerFactory: loggerFactory,
                cancellationToken: timeout.Token);

            var tools = await client.ListToolsAsync(cancellationToken: timeout.Token);
            Console.WriteLine($"Logged in to '{name}' ({tools.Count} tools). The tokens are in {store.Description}.");
            return 0;
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            throw new CommandFailedException(1, $"No login came back within {_loginTimeout.TotalMinutes:0} minutes.");
        }
        catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException or McpException or TokenStoreException)
        {
            throw new CommandFailedException(1, $"Login to '{name}' failed: {ex.Message}");
        }
    }

    private static int Status(string[] args)
    {
        var servers = Load(args).Where(server => server.OAuth is not null).ToList();
        if (servers.Count == 0)
        {
            Console.WriteLine("No server in the servers file uses OAuth (x-guardrails.oauth).");
            return 0;
        }

        var (store, warning) = CliTokenStore.Create();
        if (warning is not null)
        {
            Console.Error.WriteLine($"warning: {warning}");
        }

        Console.WriteLine($"tokens: {store.Description}");
        foreach (var server in servers)
        {
            Console.WriteLine($"{server.Name}: {Describe(new StoredTokenCache(store, server.Name, server.Url!).Status())}");
        }

        return 0;
    }

    private static int Logout(string[] args, string name)
    {
        OAuthServer(args, name);
        var (store, _) = CliTokenStore.Create();

        try
        {
            Console.WriteLine(store.Delete(name)
                ? $"Logged out of '{name}': its tokens are deleted from {store.Description}."
                : $"'{name}' was not logged in.");
        }
        catch (TokenStoreException ex)
        {
            throw new CommandFailedException(1, ex.Message);
        }

        return 0;
    }

    private static string Describe(LoginStatus status) => status.State switch
    {
        LoginState.LoggedIn => "logged in" +
            (status.ExpiresAt is { } expires ? $", access token expires {expires.ToUniversalTime():u}" : string.Empty) +
            (status.CanRefresh ? ", refreshed automatically" : ", no refresh token: log in again when it expires"),
        LoginState.OtherUrl => "logged in at a different URL; those tokens are not used. Run 'auth login' again",
        LoginState.Unreadable => "the stored login cannot be read. Run 'auth login' again",
        _ => "not logged in",
    };

    /// <summary>
    /// Accepts connections on the loopback listener until the authorization
    /// server's redirect arrives, and answers the browser.
    /// </summary>
    /// <remarks>
    /// A browser may ask for other things first (a favicon); those get a 404
    /// and the wait goes on. The request is read to its blank line and never
    /// further: a callback has no body.
    /// </remarks>
    private static async Task<AuthorizationResult?> WaitForCallbackAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        while (true)
        {
            using var connection = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var stream = connection.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);

            var requestLine = await reader.ReadLineAsync(cancellationToken);
            while (await reader.ReadLineAsync(cancellationToken) is { Length: > 0 })
            {
            }

            if (requestLine?.Split(' ') is not [_, var target, _] ||
                !target.StartsWith(LoopbackCallback.Path, StringComparison.Ordinal))
            {
                await RespondAsync(stream, "404 Not Found", string.Empty, cancellationToken);
                continue;
            }

            try
            {
                var result = LoopbackCallback.Parse(requestLine);
                await RespondAsync(stream, "200 OK", LoopbackCallback.Page(succeeded: true), cancellationToken);
                return result;
            }
            catch (InvalidOperationException)
            {
                await RespondAsync(stream, "400 Bad Request", LoopbackCallback.Page(succeeded: false), cancellationToken);
                throw;
            }
        }
    }

    private static async Task RespondAsync(NetworkStream stream, string status, string html, CancellationToken cancellationToken)
    {
        var body = Encoding.UTF8.GetBytes(html);
        var head = Encoding.ASCII.GetBytes(
            $"HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {body.Length}\r\n" +
            "Cache-Control: no-store\r\nConnection: close\r\n\r\n");

        await stream.WriteAsync(head, cancellationToken);
        await stream.WriteAsync(body, cancellationToken);
    }

    /// <remarks>
    /// The platform's handler for a URL; a failure is not fatal, because the URL
    /// is printed and can be opened by hand.
    /// </remarks>
    private static void OpenBrowser(Uri url)
    {
        try
        {
            using var _ = Process.Start(new ProcessStartInfo(url.AbsoluteUri) { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or PlatformNotSupportedException)
        {
            Console.WriteLine("Could not open a browser; open the URL above yourself.");
        }
    }

    /// <summary>The named server, which must exist and use OAuth.</summary>
    private static UpstreamServerConfig OAuthServer(string[] args, string name)
    {
        var server = Load(args).FirstOrDefault(s => s.Name == name)
                     ?? throw new CommandFailedException(1, $"There is no server '{name}' in the servers file.");

        return server.OAuth is not null
            ? server
            : throw new CommandFailedException(
                1, $"Server '{name}' does not use OAuth. Add 'x-guardrails: {{ oauth: {{}} }}' to it in the servers file.");
    }

    private static IReadOnlyList<UpstreamServerConfig> Load(string[] args)
    {
        var path = CliServers.Path(args)
                   ?? throw new CommandFailedException(1, "There is no servers file, so there are no remote servers to log in to.");

        var result = ServersLoader.LoadFile(path, CliHost.Environment);
        if (!result.IsValid)
        {
            CliServers.Report(result, Console.Error);
            throw new CommandFailedException(1, $"Invalid servers file '{path}'.");
        }

        return result.Servers;
    }

    private static List<string> Operands(string[] args)
    {
        var operands = new List<string>();
        var start = Array.IndexOf(args, "auth") + 1;

        for (var i = start; i < args.Length; i++)
        {
            if (args[i] is "--servers")
            {
                i++;
            }
            else if (!args[i].StartsWith("--", StringComparison.Ordinal))
            {
                operands.Add(args[i]);
            }
        }

        return operands;
    }
}
