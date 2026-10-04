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
                warnings.Add($"{_prefix} ignoring client-only key(s) {string.Join(", ", ignored.Select(k => $"'{k}'"))}; they configure the client, not the proxy." +
                             (ignored.Contains("oauth")
                                 ? " To have the proxy log in to this server, add 'x-guardrails: { oauth: {} }' and run 'mcp-guardrails auth login'."
                                 : string.Empty));
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

            var isolationDocument = document.Guardrails?.Isolation;
            if (isolationDocument is not null)
            {
                ForbidWhenIsolated(document);
            }

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

            // An isolated server's command runs inside the image, so whether the
            // host has it on PATH says nothing; the runtime is checked instead.
            if (command is not null && isolationDocument is null && CommandLocator.Check(command, host) is { } problem)
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
            if (document.Cwd is not null && isolationDocument is null && Expand(document.Cwd, "cwd") is { } cwd)
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

            var container = isolationDocument is null ? null : ReadIsolation(isolationDocument, own);

            if (command is null || HasNewErrors)
            {
                return null;
            }

            if (PackageRunners.FindUnpinned(command, arguments) is { } package)
            {
                warnings.Add($"{_prefix} runs '{package}' through a package runner without a pinned version, " +
                             "so every start may run a different release. Pin it, e.g. 'package@1.2.3'.");
            }

            if (container is { } isolated)
            {
                return new UpstreamServerConfig
                {
                    Name = name,
                    Transport = UpstreamTransport.Stdio,
                    Command = isolated.Expanded.Executable,
                    Arguments = isolated.Expanded.RunArguments(name, command, arguments, own.Keys),

                    // The runtime CLI gets what it needs to reach its daemon, plus
                    // the server's own variables so each '-e NAME' has a value to
                    // copy. Nothing else of the proxy's environment, isolation or not.
                    EnvironmentVariables = EnvironmentIsolation.ChildEnvironment(
                        host, EnvironmentIsolation.ContainerRuntimePassthrough, own),
                    InheritEnvironment = false,
                    ShutdownTimeout = shutdown,
                    Optional = document.Optional is true,
                    Isolation = isolated.Expanded,
                    DisplayTemplate = Display(DisplayCommandLine(
                        isolated.Display.Executable,
                        isolated.Display.RunArguments(name, document.Command, templateArgs, own.Keys))),
                };
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
            Forbid(document.Guardrails?.Isolation, "x-guardrails.isolation", Remote);

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

        private void ForbidWhenIsolated(ServerEntryDocument document)
        {
            if (document.Cwd is not null)
            {
                Error("runs in a container but sets 'cwd'. The command runs inside the image, where host " +
                      "directories do not exist; mount what it needs under 'x-guardrails.isolation.mounts'.");
            }

            if (document.EnvPassthrough is not null)
            {
                Error("runs in a container but sets 'env_passthrough'. A container gets only the variables " +
                      "declared in 'env'; pass one on with 'env: { NAME: ${NAME} }'.");
            }

            if (document.EnvIsolation is not null)
            {
                Error("runs in a container but sets 'env_isolation'. A container is always isolated: it gets " +
                      "only the variables declared in 'env'.");
            }
        }

        /// <summary>
        /// Reads <c>x-guardrails.isolation</c> twice over: once expanded, to launch,
        /// and once from the file's own text, to display.
        /// </summary>
        private (ContainerIsolation Expanded, ContainerIsolation Display)? ReadIsolation(
            ServerIsolationDocument document, Dictionary<string, string?> own)
        {
            const string Field = "x-guardrails.isolation";
            var errorsBefore = errors.Count;

            var runtime = ReadRuntime(document.Runtime);

            string? image = null;
            if (string.IsNullOrWhiteSpace(document.Image))
            {
                Error($"needs '{Field}.image', the container image to run the server in.");
            }
            else if (Expand(document.Image, $"{Field}.image") is { } expandedImage)
            {
                if (expandedImage.Length == 0 || expandedImage[0] == '-' || expandedImage.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)))
                {
                    Error($"'{Field}.image' '{document.Image}' is not an image reference.");
                }
                else
                {
                    image = expandedImage;
                    if (!expandedImage.Contains("@sha256:", StringComparison.Ordinal))
                    {
                        warnings.Add($"{_prefix} '{Field}.image' '{document.Image}' is not pinned by digest, so the " +
                                     "tag can be moved to a different image. Pin it, e.g. 'image@sha256:...'.");
                    }
                }
            }

            var network = document.Network ?? "none";
            switch (network)
            {
                case "none" or "bridge":
                    break;
                case "host":
                    Error($"'{Field}.network' is 'host', which shares the host's network and undoes the " +
                          "isolation. Use none, or bridge for ordinary outbound access.");
                    break;
                case "allowlist":
                    Error($"'{Field}.network: allowlist' is not supported yet. Use none, or bridge for " +
                          "ordinary outbound access.");
                    break;
                default:
                    Error($"'{Field}.network' '{network}' is not one of none, bridge.");
                    break;
            }

            var mounts = ReadMounts(document.Mounts ?? [], $"{Field}.mounts");

            var memory = document.Memory ?? ContainerIsolation.DefaultMemory;
            if (!IsMemorySize(memory))
            {
                Error($"'{Field}.memory' '{memory}' is not a size such as 512m or 2g.");
            }

            var cpus = document.Cpus ?? ContainerIsolation.DefaultCpus;
            if (!(cpus > 0))
            {
                Error($"'{Field}.cpus' must be a number greater than 0.");
            }

            var pids = document.PidsLimit ?? ContainerIsolation.DefaultPidsLimit;
            if (pids < 1)
            {
                Error($"'{Field}.pids_limit' must be at least 1.");
            }

            var user = ReadUser(document.User, $"{Field}.user");

            foreach (var key in own.Keys)
            {
                if (!VariableExpander.IsValidName(key))
                {
                    Error($"'env.{key}' is not a variable name, so it cannot be passed into the container.");
                }
                else if (EnvironmentIsolation.IsPassed(key, EnvironmentIsolation.ContainerRuntimePassthrough))
                {
                    Error($"runs in a container but sets 'env.{key}', which the container runtime's own " +
                          "command reads too. Set it in the image instead.");
                }
            }

            if (errors.Count > errorsBefore)
            {
                return null;
            }

            var expanded = new ContainerIsolation
            {
                Runtime = runtime!.Value,
                Image = image!,
                Network = network,
                Mounts = [.. mounts.Select(m => m.Expanded)],
                ReadOnlyRoot = document.ReadOnlyRoot ?? true,
                Memory = memory,
                Cpus = cpus,
                PidsLimit = pids,
                User = user!,
            };

            return (expanded, expanded with
            {
                Image = document.Image!,
                Mounts = [.. mounts.Select(m => m.Display)],
            });
        }

        /// <remarks>
        /// An explicit runtime that is missing is an error, and so is detection
        /// finding none: the proxy never falls back to running an isolated server
        /// directly on the host.
        /// </remarks>
        private ContainerRuntime? ReadRuntime(string? requested)
        {
            const string Never = "The proxy never runs an isolated server outside its container.";

            ContainerRuntime[] candidates = requested switch
            {
                null => [ContainerRuntime.Docker, ContainerRuntime.Podman],
                "docker" => [ContainerRuntime.Docker],
                "podman" => [ContainerRuntime.Podman],
                _ => [],
            };

            if (candidates.Length == 0)
            {
                Error($"'x-guardrails.isolation.runtime' '{requested}' is not one of docker, podman.");
                return null;
            }

            foreach (var candidate in candidates)
            {
                if (CommandLocator.Check(ContainerIsolation.ExecutableFor(candidate), host) is null)
                {
                    return candidate;
                }
            }

            Error(requested is null
                ? $"runs in a container, but neither docker nor podman was found on PATH. Install one. {Never}"
                : $"runs in a container with '{requested}', which was not found on PATH. {Never}");
            return null;
        }

        private List<(ContainerMount Expanded, ContainerMount Display)> ReadMounts(
            IReadOnlyList<ContainerMountDocument> documents, string field)
        {
            var mounts = new List<(ContainerMount, ContainerMount)>();
            var targets = new HashSet<string>(StringComparer.Ordinal);

            for (var i = 0; i < documents.Count; i++)
            {
                var document = documents[i];
                var at = $"'{field}[{i}]'";

                if (document is null || string.IsNullOrWhiteSpace(document.Host) || string.IsNullOrWhiteSpace(document.Container))
                {
                    Error($"{at} needs both 'host' and 'container' paths.");
                    continue;
                }

                MountMode? mode = document.Mode switch
                {
                    null or "ro" => MountMode.ReadOnly,
                    "rw" => MountMode.ReadWrite,
                    _ => null,
                };

                if (mode is null)
                {
                    Error($"{at} has mode '{document.Mode}'; use ro or rw.");
                }

                var hostPath = Expand(document.Host, $"{field}[{i}].host") is { } expandedHost
                    ? Path.GetFullPath(expandedHost, baseDirectory)
                    : null;
                var containerPath = Expand(document.Container, $"{field}[{i}].container");

                if (hostPath is null || containerPath is null || mode is null)
                {
                    continue;
                }

                if (!CanBeMounted(hostPath) || !CanBeMounted(containerPath))
                {
                    Error($"{at} has a path containing a comma, a quote or a control character, which a " +
                          "mount cannot express.");
                    continue;
                }

                if (!host.DirectoryExists(hostPath) && !host.FileExists(hostPath))
                {
                    Error($"{at} host path '{document.Host}' does not exist.");
                    continue;
                }

                if (Path.GetFileName(hostPath) is "docker.sock" or "podman.sock")
                {
                    Error($"{at} mounts a container runtime's socket. Whoever holds it controls the host, " +
                          "which is the opposite of isolation.");
                    continue;
                }

                if (!containerPath.StartsWith('/') || containerPath.Trim('/').Length == 0)
                {
                    Error($"{at} container path '{document.Container}' must be absolute, and not '/'.");
                    continue;
                }

                if (!targets.Add(containerPath.TrimEnd('/')))
                {
                    Error($"{at} mounts onto '{document.Container}' a second time.");
                    continue;
                }

                if (Contains(hostPath, host.HomeDirectory))
                {
                    warnings.Add($"{_prefix} {at} mounts '{document.Host}', which holds your whole home directory " +
                                 "(SSH keys, cloud credentials, browser profiles). Mount only the folder the server needs.");
                }

                mounts.Add((
                    new ContainerMount(hostPath, containerPath, mode.Value),
                    new ContainerMount(document.Host, document.Container, mode.Value)));
            }

            return mounts;
        }

        private string? ReadUser(string? requested, string field)
        {
            if (requested is null)
            {
                if (host.UserAndGroup() is { } own)
                {
                    return own;
                }

                if (!host.IsWindows)
                {
                    warnings.Add($"{_prefix} could not read your user id, so the container runs as nobody " +
                                 $"({ContainerIsolation.FallbackUser}) and may be unable to write to read-write mounts. " +
                                 $"Set '{field}'.");
                }

                return ContainerIsolation.FallbackUser;
            }

            var parts = requested.Split(':');
            if (parts.Length > 2 || parts.Any(part => part.Length == 0 || part[0] == '-' ||
                                                      !part.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '.' or '-')))
            {
                Error($"'{field}' '{requested}' is not a user such as 1000:1000.");
                return null;
            }

            if (parts[0] is "0" or "root")
            {
                warnings.Add($"{_prefix} '{field}' runs the server as root inside its container. Capabilities are " +
                             "still dropped, but a non-root user is one more barrier.");
            }

            return requested;
        }

        private static bool CanBeMounted(string path) =>
            !path.Any(c => c is ',' or '"' || char.IsControl(c));

        /// <summary>Whether mounting <paramref name="mounted"/> exposes <paramref name="inner"/>.</summary>
        private static bool Contains(string mounted, string inner)
        {
            var outer = mounted.TrimEnd('/', '\\');
            return inner == outer ||
                   inner.StartsWith(outer + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
                   outer.Length == 0;
        }

        /// <summary>Digits with an optional b, k, m or g unit: the sizes Docker and Podman accept.</summary>
        private static bool IsMemorySize(string text)
        {
            var digits = text.Length > 0 && char.ToLowerInvariant(text[^1]) is 'b' or 'k' or 'm' or 'g'
                ? text[..^1]
                : text;
            return digits.Length is > 0 and <= 12 && digits.All(char.IsAsciiDigit) && digits.Any(c => c != '0');
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
