using System.Text.Json;
using System.Text.Json.Nodes;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Scanners;
using McpGuardrails.Core.Serialization;

namespace McpGuardrails.Core.Upstream;

public static partial class ServersLoader
{
    /// <summary>Turns one server entry into a config, reporting into the shared lists.</summary>
    private sealed class ServerBuilder(
        string name,
        string baseDirectory,
        HostEnvironment host,
        ServerDefaultsDocument defaults,
        List<string> errors,
        List<string> warnings)
    {
        private readonly string _prefix = $"Server '{name}':";
        private int _errorsAtStart;

        public bool IsDisabled { get; private set; }

        public UpstreamServerConfig? Build(JsonNode? node)
        {
            _errorsAtStart = errors.Count;

            if (!UpstreamServerConfig.IsValidName(name))
            {
                Error("the name is invalid. Use letters, digits and hyphens only; '__' separates the " +
                      "server from the tool in a qualified name, so underscores are not allowed.");
            }

            if (node is not JsonObject entry)
            {
                Error("must be a mapping of fields such as 'command' or 'url'.");
                return null;
            }

            var ignored = new List<string>();
            foreach (var key in entry.Select(pair => pair.Key).ToList())
            {
                if (ClientOnlyKeys.Contains(key))
                {
                    ignored.Add(key);
                    entry.Remove(key);
                }
                else if (!_serverKeys.Contains(key))
                {
                    Error($"unknown key '{key}'.");
                }
            }

            if (ignored.Count > 0)
            {
                warnings.Add($"{_prefix} ignoring client-only key(s) {string.Join(", ", ignored.Select(k => $"'{k}'"))}; they configure the client, not the proxy.");
            }

            if (HasNewErrors)
            {
                return null;
            }

            ServerEntryDocument document;
            try
            {
                document = entry.Deserialize(GuardrailsJsonContext.Default.ServerEntryDocument)!;
            }
            catch (JsonException ex)
            {
                Error($"is not valid: {ex.Message}");
                return null;
            }

            if (document.Disabled is true)
            {
                IsDisabled = true;
                return null;
            }

            var transport = ReadTransport(document);
            var config = transport switch
            {
                UpstreamTransport.Stdio => BuildStdio(document),
                null => null,
                _ => BuildRemote(document, transport.Value),
            };

            return HasNewErrors ? null : config;
        }

        private bool HasNewErrors => errors.Count > _errorsAtStart;

        private void Error(string message) => errors.Add($"{_prefix} {message}");

        private UpstreamTransport? ReadTransport(ServerEntryDocument document)
        {
            switch (document.Type)
            {
                case null when document.Url is not null:
                    Error("has a 'url' but no 'type'. Add 'type: http' (Streamable HTTP) or 'type: sse'.");
                    return null;
                case null when document.Command is null:
                    Error("needs a 'command' (a local stdio server) or a 'type' and 'url' (a remote one).");
                    return null;
                case null or "stdio":
                    return UpstreamTransport.Stdio;
                case "http" or "streamable-http":
                    return UpstreamTransport.Http;
                case "sse":
                    return UpstreamTransport.Sse;
                case "ws":
                    Error("uses 'type: ws', which the proxy does not support. Use http or sse.");
                    return null;
                default:
                    Error($"has an unknown 'type' '{document.Type}'. Use stdio, http or sse.");
                    return null;
            }
        }

        private UpstreamServerConfig? BuildStdio(ServerEntryDocument document)
        {
            Forbid(document.Url, "url", "a stdio server");
            Forbid(document.Headers, "headers", "a stdio server");
            Forbid(document.Guardrails?.OAuth, "x-guardrails.oauth", "a stdio server");

            if (string.IsNullOrWhiteSpace(document.Command))
            {
                Error("needs a 'command'.");
                return null;
            }

            if (document.EnvFile is not null && document.EnvFileCamel is not null)
            {
                Error("has both 'env_file' and 'envFile'. Keep one.");
            }

            var command = Expand(document.Command, "command");
            if (command is not null && CommandLocator.Check(command, host) is { } problem)
            {
                Error($"'command' '{document.Command}' {problem}.");
            }

            var templateArgs = document.Args ?? [];
            var arguments = new List<string>();
            for (var i = 0; i < templateArgs.Count; i++)
            {
                arguments.Add(Expand(templateArgs[i], $"args[{i}]") ?? string.Empty);
            }

            string? workingDirectory = null;
            if (document.Cwd is not null && Expand(document.Cwd, "cwd") is { } cwd)
            {
                workingDirectory = Path.GetFullPath(cwd, baseDirectory);
                if (!host.DirectoryExists(workingDirectory))
                {
                    Error($"'cwd' '{document.Cwd}' is not an existing directory.");
                }
            }

            var own = ReadEnvFile(document.EnvFile ?? document.EnvFileCamel);
            foreach (var (key, value) in document.Env ?? new Dictionary<string, JsonElement>())
            {
                own[key] = EnvValue(key, value);
            }

            TimeSpan? shutdown = Duration(document.ShutdownTimeout ?? defaults.ShutdownTimeout);

            if (command is null || HasNewErrors)
            {
                return null;
            }

            if (PackageRunners.FindUnpinned(command, arguments) is { } package)
            {
                warnings.Add($"{_prefix} runs '{package}' through a package runner without a pinned version, " +
                             "so every start may run a different release. Pin it, e.g. 'package@1.2.3'.");
            }

            var (inherit, environment) = Isolate(document, own);

            return new UpstreamServerConfig
            {
                Name = name,
                Transport = UpstreamTransport.Stdio,
                Command = command,
                Arguments = arguments,
                EnvironmentVariables = environment,
                InheritEnvironment = inherit,
                WorkingDirectory = workingDirectory,
                ShutdownTimeout = shutdown,
                Optional = document.Optional is true,
                DisplayTemplate = Display(DisplayCommandLine(document.Command, templateArgs)),
            };
        }

        private UpstreamServerConfig? BuildRemote(ServerEntryDocument document, UpstreamTransport transport)
        {
            const string Remote = "a remote server";
            Forbid(document.Command, "command", Remote);
            Forbid(document.Args, "args", Remote);
            Forbid(document.Env, "env", Remote);
            Forbid(document.EnvFile ?? document.EnvFileCamel, "env_file", Remote);
            Forbid(document.Cwd, "cwd", Remote);
            Forbid(document.ShutdownTimeout, "shutdown_timeout", Remote);
            Forbid(document.EnvPassthrough, "env_passthrough", Remote);
            Forbid(document.EnvIsolation, "env_isolation", Remote);

            if (string.IsNullOrWhiteSpace(document.Url))
            {
                Error("needs a 'url'.");
                return null;
            }

            Uri? url = null;
            if (Expand(document.Url, "url") is { } expanded)
            {
                try
                {
                    url = OutboundUrl.Validate(
                        expanded,
                        $"servers.{name}.url",
                        reason: "Tool calls, results and the configured headers would cross the network in clear text",
                        credentialHint: "send it in 'headers' as a ${VAR} reference instead",
                        allowLoopbackHttp: true);
                }
                catch (PolicyException ex)
                {
                    Error(ex.Message);
                }
            }

            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (key, value) in document.Headers ?? new Dictionary<string, string>())
            {
                headers[key] = Expand(value, $"headers.{key}") ?? string.Empty;
            }

            var oauth = document.Guardrails?.OAuth is { } oauthDocument
                ? UpstreamOAuthSettings.Read(oauthDocument, headers, Error)
                : null;

            if (url is null || HasNewErrors)
            {
                return null;
            }

            return new UpstreamServerConfig
            {
                Name = name,
                Transport = transport,
                Url = url,
                Headers = headers,
                OAuth = oauth,
                Optional = document.Optional is true,
                DisplayTemplate = Display(document.Url),
            };
        }

        private (bool Inherit, IReadOnlyDictionary<string, string?> Environment) Isolate(
            ServerEntryDocument document, Dictionary<string, string?> own)
        {
            var isolation = document.EnvIsolation ?? defaults.EnvIsolation;
            IReadOnlyList<string> passthrough = [.. defaults.EnvPassthrough ?? [], .. document.EnvPassthrough ?? []];

            if (isolation is true)
            {
                if (passthrough.Contains(EnvironmentIsolation.Everything))
                {
                    warnings.Add($"{_prefix} 'env_passthrough' contains '*', so it inherits the proxy's whole " +
                                 "environment and isolation does nothing for it.");
                    return (true, own);
                }

                return (false, EnvironmentIsolation.ChildEnvironment(host, passthrough, own));
            }

            IReadOnlyList<string> withheld = isolation is null
                ? EnvironmentIsolation.WouldWithhold(host, passthrough, own)
                : [];
            if (withheld.Count > 0)
            {
                warnings.Add(
                    $"{_prefix} inherits the proxy's whole environment. A future release will isolate stdio " +
                    $"servers by default, withholding: {string.Join(", ", withheld)}. Set 'env_isolation: true' " +
                    "now (and list what it needs in 'env_passthrough'), or 'env_isolation: false' to keep inheriting.");
            }

            return (true, own);
        }

        private Dictionary<string, string?> ReadEnvFile(string? template)
        {
            if (template is null || Expand(template, "env_file") is not { } path)
            {
                return new Dictionary<string, string?>(StringComparer.Ordinal);
            }

            string text;
            try
            {
                text = host.ReadAllText(Path.GetFullPath(path, baseDirectory));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Error($"'env_file' '{template}' could not be read: {ex.Message}");
                return new Dictionary<string, string?>(StringComparer.Ordinal);
            }

            var variables = EnvFile.Parse(text, out var error);
            if (variables is null)
            {
                Error($"'env_file' '{template}': {error}.");
                return new Dictionary<string, string?>(StringComparer.Ordinal);
            }

            return variables;
        }

        private string? EnvValue(string key, JsonElement value)
        {
            switch (value.ValueKind)
            {
                case JsonValueKind.String:
                    return Expand(value.GetString()!, $"env.{key}");
                case JsonValueKind.Number:
                    return value.GetRawText();
                case JsonValueKind.True:
                    return "true";
                case JsonValueKind.False:
                    return "false";
                case JsonValueKind.Null:
                    return null;
                default:
                    Error($"'env.{key}' must be a string, number, boolean or null.");
                    return null;
            }
        }

        private TimeSpan? Duration(JsonElement? element)
        {
            if (element is not { } value)
            {
                return null;
            }

            if (Durations.TryParse(value, out var duration))
            {
                return duration;
            }

            Error("'shutdown_timeout' must be a duration such as 5s, 500ms or 2m.");
            return null;
        }

        private void Forbid(object? value, string field, string what)
        {
            if (value is not null)
            {
                Error($"is {what} but sets '{field}', which only applies to " +
                      (what == "a stdio server" ? "remote servers." : "stdio servers."));
            }
        }

        private string? Expand(string template, string field)
        {
            var expansion = VariableExpander.Expand(template, host.GetVariable);
            if (!expansion.Succeeded)
            {
                Error($"'{field}' {expansion.Error}");
            }

            return expansion.Value;
        }

        /// <summary>
        /// The template as it may be shown, with anything shaped like a secret
        /// that was written into the file literally masked.
        /// </summary>
        private static string Display(string template) =>
            SecretScanner.Redact(template, includePii: false).Text;
    }
}
