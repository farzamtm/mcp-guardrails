using System.Text.Json.Nodes;

namespace McpGuardrails.Core.Scanners;

/// <summary>The <c>scan</c> command line was not usable.</summary>
public sealed class ScanOptionsException(string message) : Exception(message);

/// <summary>
/// What <c>scan</c> was asked to do: which servers, and how to print the report.
/// </summary>
/// <remarks>
/// <c>--command</c> takes the rest of the line, so a server's own flags
/// (<c>npx -y pkg --json</c>) are never read as the proxy's. Only what comes
/// before it is parsed, and an unknown flag there is an error rather than
/// ignored: a misspelt <c>--sever</c> silently scanning something else would
/// produce a clean report about the wrong thing.
/// </remarks>
public sealed record ScanOptions
{
    /// <summary>The server name a <c>--command</c> or <c>--url</c> target is scanned under.</summary>
    public const string TargetName = "target";

    /// <summary>Print the report as JSON instead of text.</summary>
    public bool Json { get; init; }

    /// <summary>The <c>--servers</c> file, when given.</summary>
    public string? ServersPath { get; init; }

    /// <summary>
    /// A one-server servers document for the <c>--command</c> or <c>--url</c>
    /// target, or null to scan the configured servers.
    /// </summary>
    /// <remarks>
    /// A document rather than a config so the target goes through
    /// <see cref="Upstream.ServersLoader"/> like any configured server: the command
    /// must resolve, the URL must be https or loopback, an unpinned package runner
    /// is warned about. One set of rules, not a second, laxer one for ad-hoc use.
    /// </remarks>
    public string? TargetDocument { get; init; }

    private static readonly string[] _known = ["--json", "--servers", "--url", "--sse", "--header", "--command"];

    /// <summary>Parses the command line.</summary>
    /// <param name="args">The full command line, including the word <c>scan</c>.</param>
    /// <exception cref="ScanOptionsException">The line is contradictory, incomplete or has an unknown flag.</exception>
    public static ScanOptions Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        var commandAt = IndexOf(args, "--command");
        var own = commandAt < 0 ? args : args.Take(commandAt).ToList();

        string? servers = null;
        string? url = null;
        var sse = false;
        var json = false;
        var headers = new List<string>();

        for (var i = 0; i < own.Count; i++)
        {
            switch (own[i])
            {
                case "--json":
                    json = true;
                    break;
                case "--sse":
                    sse = true;
                    break;
                case "--servers":
                    servers = ValueAfter(own, ref i);
                    break;
                case "--url":
                    url = ValueAfter(own, ref i);
                    break;
                case "--header":
                    headers.Add(ValueAfter(own, ref i));
                    break;
                case var flag when flag.StartsWith("--", StringComparison.Ordinal):
                    throw new ScanOptionsException(
                        $"scan does not know the flag '{flag}'. Known: {string.Join(", ", _known)}.");
            }
        }

        var command = commandAt < 0 ? null : args.Skip(commandAt + 1).ToList();

        if (command is not null && url is not null)
        {
            throw new ScanOptionsException("Give --command or --url, not both: scan looks at one target at a time.");
        }

        if (command is { Count: 0 })
        {
            throw new ScanOptionsException("--command needs the server's command line after it, e.g. --command npx -y pkg@1.2.3.");
        }

        if ((command is not null || url is not null) && servers is not null)
        {
            throw new ScanOptionsException(
                "--servers scans the configured servers; --command and --url scan one target instead. Give one or the other.");
        }

        if (url is null && (sse || headers.Count > 0))
        {
            throw new ScanOptionsException("--sse and --header only apply to a --url target.");
        }

        return new ScanOptions
        {
            Json = json,
            ServersPath = servers,
            TargetDocument = command is not null ? StdioDocument(command)
                : url is not null ? RemoteDocument(url, sse, headers)
                : null,
        };
    }

    /// <summary>The target as a stdio server.</summary>
    /// <remarks>
    /// Isolated: the scanned server gets the built-in allowlist (<c>PATH</c>,
    /// <c>HOME</c> and the like) and none of the scanner's environment. A server
    /// someone is scanning is one they have not decided to trust yet, and the
    /// shell it is scanned from is likely to hold API keys. A server that needs a
    /// token to start belongs in a servers file, where it is passed explicitly.
    /// </remarks>
    private static string StdioDocument(IReadOnlyList<string> command)
    {
        var args = new JsonArray();
        foreach (var argument in command.Skip(1))
        {
            args.Add((JsonNode)Literal(argument));
        }

        return Document(new JsonObject
        {
            ["command"] = Literal(command[0]),
            ["args"] = args,
            ["env_isolation"] = true,
        });
    }

    private static string RemoteDocument(string url, bool sse, IReadOnlyList<string> headerLines)
    {
        var headers = new JsonObject();
        foreach (var line in headerLines)
        {
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0)
            {
                // The value is not echoed: a malformed header line is most often
                // an Authorization header missing its colon.
                throw new ScanOptionsException("--header takes 'Name: value', with a colon after the name.");
            }

            headers[line[..colon].Trim()] = Literal(line[(colon + 1)..].Trim());
        }

        return Document(new JsonObject
        {
            ["type"] = sse ? "sse" : "http",
            ["url"] = Literal(url),
            ["headers"] = headers,
        });
    }

    private static string Document(JsonObject server) =>
        new JsonObject
        {
            ["version"] = Upstream.ServersLoader.CurrentVersion,
            ["servers"] = new JsonObject { [TargetName] = server },
        }.ToJsonString();

    /// <summary>A command-line word as the servers file would need it written.</summary>
    /// <remarks>
    /// The shell has already expanded what it was going to, so a <c>$</c> that is
    /// left is meant literally and must not become a <c>${VAR}</c> reference.
    /// </remarks>
    private static string Literal(string value) => value.Replace("$", "$$", StringComparison.Ordinal);

    private static int IndexOf(IReadOnlyList<string> args, string flag)
    {
        for (var i = 0; i < args.Count; i++)
        {
            if (args[i] == flag)
            {
                return i;
            }
        }

        return -1;
    }

    private static string ValueAfter(IReadOnlyList<string> args, ref int i)
    {
        var flag = args[i];
        if (i + 1 >= args.Count || args[i + 1].StartsWith("--", StringComparison.Ordinal))
        {
            throw new ScanOptionsException($"{flag} needs a value.");
        }

        return args[++i];
    }
}
