using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Tests.Upstream;

/// <summary>
/// <c>x-guardrails.isolation</c> in the servers file: the strict defaults, every
/// validation rule, and that a container never inherits the proxy's environment.
/// </summary>
public sealed class ServersLoaderIsolationTests
{
    private const string _image = "ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:0123";

    private static readonly string _base = FakeHost.At("config");
    private static readonly string _sandbox = FakeHost.At("srv", "sandbox");

    private static ServersLoadResult Parse(string isolation, FakeHost? host = null, string extra = "")
    {
        host ??= new FakeHost();
        host.Directories.Add(_sandbox);

        return ServersLoader.Parse(
            $$"""
            version: 1
            servers:
              fetch:
                command: uvx
                args: ["mcp-server-fetch==2025.4.7"]
            {{extra}}
                x-guardrails:
                  isolation:
            {{isolation}}
            """,
            _base,
            host.Build());
    }

    private static UpstreamServerConfig Single(string isolation, FakeHost? host = null, string extra = "")
    {
        var result = Parse(isolation, host, extra);
        Assert.True(result.IsValid, string.Join("\n", result.Errors));
        return Assert.Single(result.Servers);
    }

    private static string SingleError(string isolation, FakeHost? host = null, string extra = "")
    {
        var result = Parse(isolation, host, extra);
        Assert.Empty(result.Servers);
        return Assert.Single(result.Errors);
    }

    private static string Quoted(string path) => path.Replace(@"\", @"\\", StringComparison.Ordinal);

    // ------------------------------------------------------------ the launch

    [Fact]
    public void AnIsolatedServer_LaunchesThroughTheRuntime_WithStrictDefaults()
    {
        var host = new FakeHost();
        host.Variables["ANTHROPIC_API_KEY"] = "proxy-secret";
        host.Variables["DOCKER_HOST"] = "unix:///run/docker.sock";
        host.Variables["FETCH_TOKEN"] = "fetch-secret";

        var config = Single($"""
                    image: {_image}
            """, host, """
                env:
                  FETCH_TOKEN: ${FETCH_TOKEN}
            """);

        Assert.Equal("docker", config.Command);
        Assert.Equal(
            [
                "run", "-i", "--rm", "--label", "mcp-guardrails.server=fetch", "--network", "none",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256",
                "--memory", "512m", "--cpus", "1", "--user", "1000:1000", "--read-only",
                "--tmpfs", ContainerIsolation.ScratchMount, "-e", "HOME=/tmp",
                "-e", "FETCH_TOKEN",
                _image, "uvx", "mcp-server-fetch==2025.4.7",
            ],
            config.Arguments);

        // The runtime CLI reaches its daemon and has the value to copy in; the
        // proxy's own secrets reach neither it nor the container.
        Assert.False(config.InheritEnvironment);
        Assert.Equal("fetch-secret", config.EnvironmentVariables!["FETCH_TOKEN"]);
        Assert.Equal("unix:///run/docker.sock", config.EnvironmentVariables["DOCKER_HOST"]);
        Assert.False(config.EnvironmentVariables.ContainsKey("ANTHROPIC_API_KEY"));
        Assert.DoesNotContain(config.Arguments, a => a.Contains("fetch-secret", StringComparison.Ordinal));

        Assert.NotNull(config.Isolation);
        Assert.StartsWith("docker container from ", config.Reach(), StringComparison.Ordinal);
    }

    [Fact]
    public void TheDisplayedCommand_KeepsTheFilesTemplates()
    {
        var host = new FakeHost();
        host.Variables["SANDBOX"] = _sandbox;
        host.Variables["TAG"] = "sha256:0123";

        var config = Single("""
                    runtime: docker
                    image: ghcr.io/example/server@${TAG}
                    mounts:
                      - { host: "${SANDBOX}", container: /workspace, mode: rw }
            """, host);

        Assert.Contains($"type=bind,source={_sandbox},target=/workspace", config.Arguments, StringComparer.Ordinal);
        Assert.Contains("ghcr.io/example/server@sha256:0123", config.Arguments, StringComparer.Ordinal);

        Assert.StartsWith("docker run -i --rm ", config.DisplayTemplate, StringComparison.Ordinal);
        Assert.Contains("source=${SANDBOX},target=/workspace", config.DisplayTemplate, StringComparison.Ordinal);
        Assert.Contains("ghcr.io/example/server@${TAG} uvx", config.DisplayTemplate, StringComparison.Ordinal);
        Assert.DoesNotContain(_sandbox, config.DisplayTemplate, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryOption_IsRead()
    {
        var host = new FakeHost().WithCommand("podman");
        host.Directories.Add(Path.Combine(_base, "sandbox-relative"));
        var config = Single($"""
                    runtime: podman
                    image: {_image}
                    network: bridge
                    mounts:
                      - {"{"} host: "{Quoted(_sandbox)}", container: /workspace, mode: rw {"}"}
                      - {"{"} host: "sandbox-relative", container: /data {"}"}
                    read_only_root: false
                    memory: 2g
                    cpus: 0.5
                    pids_limit: 64
                    user: "1234:5678"
            """, host, """
                optional: true
            """);

        Assert.True(config.Optional);

        var isolation = config.Isolation!;
        Assert.Equal("podman", config.Command);
        Assert.Equal(ContainerRuntime.Podman, isolation.Runtime);
        Assert.Equal("bridge", isolation.Network);
        Assert.False(isolation.ReadOnlyRoot);
        Assert.Equal("2g", isolation.Memory);
        Assert.Equal(0.5, isolation.Cpus);
        Assert.Equal(64, isolation.PidsLimit);
        Assert.Equal("1234:5678", isolation.User);
        Assert.Equal(
            [
                new ContainerMount(_sandbox, "/workspace", MountMode.ReadWrite),
                new ContainerMount(Path.Combine(_base, "sandbox-relative"), "/data", MountMode.ReadOnly),
            ],
            isolation.Mounts);
    }

    [Fact]
    public void RelativeHostPaths_StartFromTheServersFile()
    {
        var host = new FakeHost();
        host.Directories.Add(Path.Combine(_base, "data"));

        var config = Single($"""
                    image: {_image}
                    mounts:
                      - {"{"} host: data, container: /data {"}"}
            """, host);

        Assert.Equal(Path.Combine(_base, "data"), config.Isolation!.Mounts[0].HostPath);
    }

    [Fact]
    public void TheCommand_IsNotLookedUpOnTheHost_BecauseItRunsInTheImage()
    {
        var host = new FakeHost().WithoutCommand("uvx");

        var config = Single($"""
                    image: {_image}
            """, host);

        Assert.Equal("uvx", config.Arguments[^2]);
    }

    [Fact]
    public void AnUnpinnedImage_IsAWarning()
    {
        var result = Parse("""
                    image: ghcr.io/astral-sh/uv:latest
            """);

        Assert.True(result.IsValid);
        Assert.Contains(result.Warnings, w => w.Contains("not pinned by digest", StringComparison.Ordinal));
    }

    [Fact]
    public void AnUnpinnedPackage_IsStillAWarning_InsideAContainer()
    {
        var result = ServersLoader.Parse(
            $"""
            servers:
              fetch:
                command: uvx
                args: ["mcp-server-fetch"]
                x-guardrails:
                  isolation:
                    image: {_image}
            """,
            _base,
            new FakeHost().Build());

        Assert.Contains(result.Warnings, w => w.Contains("without a pinned version", StringComparison.Ordinal));
    }

    // ------------------------------------------------------------ the runtime

    [Fact]
    public void Detection_PrefersDocker_ThenPodman()
    {
        var host = new FakeHost().WithoutCommand("docker").WithCommand("podman");

        var config = Single($"""
                    image: {_image}
            """, host);

        Assert.Equal("podman", config.Command);
    }

    [Fact]
    public void NoRuntime_IsAnError_NeverAnUnisolatedLaunch()
    {
        var error = SingleError($"""
                    image: {_image}
            """, new FakeHost().WithoutCommand("docker"));

        Assert.Equal(
            "Server 'fetch': runs in a container, but neither docker nor podman was found on PATH. Install one. " +
            "The proxy never runs an isolated server outside its container.",
            error);
    }

    [Fact]
    public void ANamedRuntimeThatIsMissing_IsAnError()
    {
        var error = SingleError($"""
                    runtime: podman
                    image: {_image}
            """);

        Assert.Equal(
            "Server 'fetch': runs in a container with 'podman', which was not found on PATH. " +
            "The proxy never runs an isolated server outside its container.",
            error);
    }

    [Fact]
    public void AnUnknownRuntime_IsAnError()
    {
        Assert.Equal(
            "Server 'fetch': 'x-guardrails.isolation.runtime' 'lxc' is not one of docker, podman.",
            SingleError($"""
                    runtime: lxc
                    image: {_image}
            """));
    }

    // ------------------------------------------------------------ validation

    [Fact]
    public void TheImage_IsRequired()
    {
        Assert.Equal(
            "Server 'fetch': needs 'x-guardrails.isolation.image', the container image to run the server in.",
            SingleError("""
                    network: none
            """));
    }

    [Theory]
    [InlineData("--privileged")]
    [InlineData("\"image with space\"")]
    public void AnImageThatIsNotAReference_IsAnError(string image)
    {
        Assert.Contains("is not an image reference", SingleError($"""
                    image: {image}
            """), StringComparison.Ordinal);
    }

    [Fact]
    public void AnImageThatExpandsToNothing_IsAnError()
    {
        var host = new FakeHost();
        host.Variables["EMPTY"] = string.Empty;

        Assert.Contains("is not an image reference", SingleError("""
                    image: ${EMPTY}
            """, host), StringComparison.Ordinal);
    }

    [Fact]
    public void AnImageWithAnUnsetVariable_ReportsTheVariable()
    {
        Assert.Contains("NOT_SET", SingleError("""
                    image: ${NOT_SET}
            """), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("host", "shares the host's network")]
    [InlineData("allowlist", "is not supported yet")]
    [InlineData("container:other", "is not one of none, bridge")]
    public void Networks_OtherThanNoneAndBridge_AreErrors(string network, string message)
    {
        Assert.Contains(message, SingleError($"""
                    image: {_image}
                    network: "{network}"
            """), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("512")]
    [InlineData("1G")]
    [InlineData("100k")]
    [InlineData("65536b")]
    public void MemorySizes_AreAccepted(string memory)
    {
        Assert.Equal(memory, Single($"""
                    image: {_image}
                    memory: "{memory}"
            """).Isolation!.Memory);
    }

    [Theory]
    [InlineData("")]
    [InlineData("m")]
    [InlineData("0m")]
    [InlineData("1.5g")]
    [InlineData("512 m")]
    [InlineData("1t")]
    [InlineData("9999999999999m")]
    public void MemorySizes_ThatAreNotSizes_AreErrors(string memory)
    {
        Assert.Contains("is not a size such as 512m", SingleError($"""
                    image: {_image}
                    memory: "{memory}"
            """), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-1")]
    public void Cpus_MustBePositive(string cpus)
    {
        Assert.Contains("'x-guardrails.isolation.cpus' must be a number greater than 0", SingleError($"""
                    image: {_image}
                    cpus: {cpus}
            """), StringComparison.Ordinal);
    }

    [Fact]
    public void ThePidsLimit_MustBeAtLeastOne()
    {
        Assert.Contains("'x-guardrails.isolation.pids_limit' must be at least 1", SingleError($"""
                    image: {_image}
                    pids_limit: 0
            """), StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnknownKey_IsAnError()
    {
        var result = Parse($"""
                    image: {_image}
                    privileged: true
            """);

        Assert.False(result.IsValid);
        Assert.Contains("privileged", Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    // ------------------------------------------------------------ mounts

    [Fact]
    public void AMountWithoutBothPaths_IsAnError()
    {
        Assert.Equal(
            "Server 'fetch': 'x-guardrails.isolation.mounts[0]' needs both 'host' and 'container' paths.",
            SingleError($"""
                    image: {_image}
                    mounts:
                      - {"{"} container: /workspace {"}"}
            """));
    }

    [Fact]
    public void AnEmptyMountEntry_IsAnError()
    {
        Assert.Contains("needs both 'host' and 'container' paths", SingleError($"""
                    image: {_image}
                    mounts:
                      -
            """), StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnknownMountMode_IsAnError()
    {
        Assert.Contains("has mode 'rwx'; use ro or rw", SingleError($"""
                    image: {_image}
                    mounts:
                      - {"{"} host: "{Quoted(_sandbox)}", container: /workspace, mode: rwx {"}"}
            """), StringComparison.Ordinal);
    }

    [Fact]
    public void AMountWithAnUnsetVariable_ReportsTheVariable()
    {
        Assert.Contains("NOT_SET", SingleError($"""
                    image: {_image}
                    mounts:
                      - {"{"} host: "${"{"}NOT_SET{"}"}", container: /workspace {"}"}
            """), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/work,readonly=false")]
    [InlineData("/work\\\"x")]
    [InlineData("/work\\nx")]
    public void AMountPathTheMountSyntaxCannotCarry_IsAnError(string container)
    {
        Assert.Contains("which a mount cannot express", SingleError($"""
                    image: {_image}
                    mounts:
                      - {"{"} host: "{Quoted(_sandbox)}", container: "{container}" {"}"}
            """), StringComparison.Ordinal);
    }

    [Fact]
    public void AHostPathTheMountSyntaxCannotCarry_IsAnError()
    {
        var path = FakeHost.At("srv", "a,readonly=false");
        var host = new FakeHost();
        host.Directories.Add(path);

        Assert.Contains("which a mount cannot express", SingleError($"""
                    image: {_image}
                    mounts:
                      - {"{"} host: "{Quoted(path)}", container: /workspace {"}"}
            """, host), StringComparison.Ordinal);
    }

    [Fact]
    public void AMissingHostPath_IsAnError()
    {
        Assert.Contains("host path 'nowhere' does not exist", SingleError($"""
                    image: {_image}
                    mounts:
                      - {"{"} host: nowhere, container: /workspace {"}"}
            """), StringComparison.Ordinal);
    }

    [Fact]
    public void AHostFile_CanBeMounted()
    {
        var file = FakeHost.At("srv", "settings.json");
        var host = new FakeHost();
        host.Files.Add(file);

        var config = Single($"""
                    image: {_image}
                    mounts:
                      - {"{"} host: "{Quoted(file)}", container: /etc/settings.json {"}"}
            """, host);

        Assert.Equal(file, config.Isolation!.Mounts[0].HostPath);
    }

    [Theory]
    [InlineData("docker.sock")]
    [InlineData("podman.sock")]
    public void ARuntimeSocket_IsNeverMounted(string socket)
    {
        var path = FakeHost.At("var", "run", socket);
        var host = new FakeHost();
        host.Files.Add(path);

        Assert.Contains("mounts a container runtime's socket", SingleError($"""
                    image: {_image}
                    mounts:
                      - {"{"} host: "{Quoted(path)}", container: /var/run/docker.sock {"}"}
            """, host), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("workspace")]
    [InlineData("/")]
    [InlineData("//")]
    public void TheContainerPath_MustBeAbsoluteAndNotTheRoot(string container)
    {
        Assert.Contains("must be absolute, and not '/'", SingleError($"""
                    image: {_image}
                    mounts:
                      - {"{"} host: "{Quoted(_sandbox)}", container: "{container}" {"}"}
            """), StringComparison.Ordinal);
    }

    [Fact]
    public void TwoMountsOntoOnePath_IsAnError()
    {
        Assert.Contains("mounts onto '/workspace/' a second time", SingleError($"""
                    image: {_image}
                    mounts:
                      - {"{"} host: "{Quoted(_sandbox)}", container: /workspace {"}"}
                      - {"{"} host: "{Quoted(_sandbox)}", container: /workspace/ {"}"}
            """), StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(HomeExposingPaths))]
    public void MountingTheHomeDirectoryOrAParent_IsAWarning(string path)
    {
        var host = new FakeHost();
        host.Directories.Add(path);

        var result = Parse($"""
                    image: {_image}
                    mounts:
                      - {"{"} host: "{Quoted(path)}", container: /host {"}"}
            """, host);

        Assert.True(result.IsValid, string.Join("\n", result.Errors));
        Assert.Contains(result.Warnings, w => w.Contains("holds your whole home directory", StringComparison.Ordinal));
    }

    public static TheoryData<string> HomeExposingPaths() =>
        new(FakeHost.Home, FakeHost.At("home"), FakeHost.Root);

    [Fact]
    public void MountingAFolderBesideHome_IsNotAWarning()
    {
        var sibling = FakeHost.At("home", "user-data");
        var host = new FakeHost();
        host.Directories.Add(sibling);

        var result = Parse($"""
                    image: {_image}
                    mounts:
                      - {"{"} host: "{Quoted(sibling)}", container: /data {"}"}
            """, host);

        Assert.DoesNotContain(result.Warnings, w => w.Contains("home directory", StringComparison.Ordinal));
    }

    // ------------------------------------------------------------ the user

    [Fact]
    public void AnUnknownHostUser_FallsBackToNobody_WithAWarningOnUnix()
    {
        var host = new FakeHost { IsWindows = false, UserAndGroup = null };

        var result = Parse($"""
                    image: {_image}
            """, host);

        Assert.Equal(ContainerIsolation.FallbackUser, Assert.Single(result.Servers).Isolation!.User);
        Assert.Contains(result.Warnings, w => w.Contains("could not read your user id", StringComparison.Ordinal));
    }

    [Fact]
    public void OnWindows_TheContainerRunsAsNobody_Silently()
    {
        var host = new FakeHost { IsWindows = true, UserAndGroup = null };
        host.Variables["PATHEXT"] = ".EXE";
        host.WithCommand("docker").Files.Add(Path.Combine(FakeHost.Bin, "docker.EXE"));

        var result = Parse($"""
                    image: {_image}
            """, host);

        Assert.Equal(ContainerIsolation.FallbackUser, Assert.Single(result.Servers).Isolation!.User);
        Assert.DoesNotContain(result.Warnings, w => w.Contains("user id", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("1000")]
    [InlineData("app")]
    [InlineData("app:staff")]
    [InlineData("svc_user.1:grp-2")]
    public void Users_AreAccepted(string user)
    {
        Assert.Equal(user, Single($"""
                    image: {_image}
                    user: "{user}"
            """).Isolation!.User);
    }

    [Theory]
    [InlineData("1:2:3")]
    [InlineData(":1000")]
    [InlineData("--privileged")]
    [InlineData("a b")]
    [InlineData("")]
    public void UsersThatAreNotUsers_AreErrors(string user)
    {
        Assert.Contains("is not a user such as 1000:1000", SingleError($"""
                    image: {_image}
                    user: "{user}"
            """), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("root:root")]
    public void Root_IsAWarning(string user)
    {
        var result = Parse($"""
                    image: {_image}
                    user: "{user}"
            """);

        Assert.True(result.IsValid);
        Assert.Contains(result.Warnings, w => w.Contains("runs the server as root", StringComparison.Ordinal));
    }

    // ------------------------------------------------------------ the environment

    [Fact]
    public void AnEnvName_ThatIsNotAVariableName_IsAnError()
    {
        Assert.Contains("'env.MY-TOKEN' is not a variable name", SingleError($"""
                    image: {_image}
            """, extra: """
                env:
                  MY-TOKEN: x
            """), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("PATH")]
    [InlineData("HOME")]
    [InlineData("DOCKER_HOST")]
    [InlineData("XDG_RUNTIME_DIR")]
    public void AnEnvName_TheRuntimeReadsToo_IsAnError(string name)
    {
        Assert.Contains($"sets 'env.{name}', which the container runtime's own command reads too", SingleError($"""
                    image: {_image}
            """, extra: $"""
                env:
                  {name}: x
            """), StringComparison.Ordinal);
    }

    [Fact]
    public void EnvFileVariables_ArePassedByNameToo()
    {
        var host = new FakeHost();
        host.Contents[Path.Combine(_base, "fetch.env")] = "FROM_FILE=file-secret\n";

        var config = Single($"""
                    image: {_image}
            """, host, """
                env_file: fetch.env
            """);

        Assert.Contains("FROM_FILE", config.Arguments, StringComparer.Ordinal);
        Assert.Equal("file-secret", config.EnvironmentVariables!["FROM_FILE"]);
    }

    [Theory]
    [InlineData("cwd: /srv", "sets 'cwd'")]
    [InlineData("env_passthrough: [AWS_PROFILE]", "sets 'env_passthrough'")]
    [InlineData("env_isolation: false", "sets 'env_isolation'")]
    public void HostOnlyFields_AreErrorsOnAnIsolatedServer(string field, string message)
    {
        var result = Parse($"""
                    image: {_image}
            """, extra: $"""
                {field}
            """);

        Assert.Contains(result.Errors, e => e.Contains(message, StringComparison.Ordinal));
    }

    [Fact]
    public void DefaultsForHostServers_DoNotApplyToAContainer()
    {
        var host = new FakeHost();
        host.Variables["AWS_PROFILE"] = "prod";

        var result = ServersLoader.Parse(
            $"""
            defaults:
              env_passthrough: [AWS_PROFILE]
              env_isolation: false
            servers:
              fetch:
                command: uvx
                args: ["mcp-server-fetch==2025.4.7"]
                x-guardrails:
                  isolation:
                    image: {_image}
            """,
            _base,
            host.Build());

        var config = Assert.Single(result.Servers);
        Assert.False(config.InheritEnvironment);
        Assert.False(config.EnvironmentVariables!.ContainsKey("AWS_PROFILE"));
        Assert.DoesNotContain(result.Warnings, w => w.Contains("whole environment", StringComparison.Ordinal));
    }

    [Fact]
    public void IsolationOnARemoteServer_IsAnError()
    {
        var result = ServersLoader.Parse(
            $"""
            servers:
              docs:
                type: http
                url: https://mcp.example.com/mcp
                x-guardrails:
                  isolation:
                    image: {_image}
            """,
            _base,
            new FakeHost().Build());

        Assert.Contains(
            "Server 'docs': is a remote server but sets 'x-guardrails.isolation', which only applies to stdio servers.",
            result.Errors);
    }

    [Fact]
    public void EveryProblem_IsReportedTogether()
    {
        var result = Parse("""
                    runtime: lxc
                    network: host
                    memory: lots
                    pids_limit: 0
            """, extra: """
                cwd: /srv
            """);

        Assert.Equal(6, result.Errors.Count);
    }
}
