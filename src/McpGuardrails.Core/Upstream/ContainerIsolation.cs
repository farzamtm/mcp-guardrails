using System.Globalization;

namespace McpGuardrails.Core.Upstream;

/// <summary>The container CLI that launches an isolated server.</summary>
public enum ContainerRuntime
{
    Docker,
    Podman,
}

/// <summary>Whether a bind mount can be written through.</summary>
public enum MountMode
{
    ReadOnly,
    ReadWrite,
}

/// <summary>One host path made visible inside the container.</summary>
/// <param name="HostPath">The absolute path on the host.</param>
/// <param name="ContainerPath">The absolute path inside the container.</param>
/// <param name="Mode">Read-only unless the servers file says <c>rw</c>.</param>
public sealed record ContainerMount(string HostPath, string ContainerPath, MountMode Mode);

/// <summary>
/// How to run one stdio server inside a container: the servers file's
/// <c>x-guardrails.isolation</c> block, validated.
/// </summary>
/// <remarks>
/// The proxy does not talk to a container daemon. It turns this record into an
/// ordinary command line - <c>docker run -i --rm ... image command args</c> - and
/// launches that like any other stdio server. No API client, no socket handling,
/// no dependency: the runtime's own CLI already does all of that, and the
/// generated command is something an operator can read, paste and run by hand.
///
/// Every field defaults to the strict setting (no network, read-only root, all
/// capabilities dropped, bounded memory and processes, a non-root user). The
/// servers file loosens them one by one, so each loosening is a visible line in
/// a reviewed file.
/// </remarks>
public sealed record ContainerIsolation
{
    /// <summary>Memory limit when the file sets none.</summary>
    public const string DefaultMemory = "512m";

    /// <summary>CPU limit when the file sets none.</summary>
    public const double DefaultCpus = 1;

    /// <summary>Process limit when the file sets none: enough for a server, too few for a fork bomb.</summary>
    public const int DefaultPidsLimit = 256;

    /// <summary>The user an isolated server runs as when the host's cannot be determined: <c>nobody</c>.</summary>
    public const string FallbackUser = "65534:65534";

    /// <summary>The label every isolated container carries, so <c>docker ps --filter label=...</c> finds them.</summary>
    public const string ServerLabel = "mcp-guardrails.server";

    /// <summary>
    /// The writable scratch space of a read-only container, and its HOME.
    /// </summary>
    /// <remarks>
    /// Package runners (npx, uvx) unpack into a cache under HOME and then run
    /// what they unpacked, so the mount allows exec; it is the container's own
    /// memory-backed space, not the host's.
    /// </remarks>
    public const string ScratchMount = "/tmp:rw,exec,nosuid,nodev,size=256m";

    public required ContainerRuntime Runtime { get; init; }

    /// <summary>The image to run, ideally pinned by digest.</summary>
    public required string Image { get; init; }

    /// <summary><c>none</c> or <c>bridge</c>.</summary>
    public string Network { get; init; } = "none";

    public IReadOnlyList<ContainerMount> Mounts { get; init; } = [];

    public bool ReadOnlyRoot { get; init; } = true;

    /// <summary>A Docker memory size such as <c>512m</c>.</summary>
    public string Memory { get; init; } = DefaultMemory;

    public double Cpus { get; init; } = DefaultCpus;

    public int PidsLimit { get; init; } = DefaultPidsLimit;

    /// <summary><c>uid:gid</c> (or names) the server runs as inside the container.</summary>
    public string User { get; init; } = FallbackUser;

    /// <summary>The runtime CLI's executable name, looked up on PATH.</summary>
    public string Executable => ExecutableFor(Runtime);

    /// <summary>The executable name of <paramref name="runtime"/>'s CLI.</summary>
    public static string ExecutableFor(ContainerRuntime runtime) =>
        runtime is ContainerRuntime.Podman ? "podman" : "docker";

    /// <summary>
    /// The runtime CLI's arguments that start <paramref name="command"/> inside
    /// the container.
    /// </summary>
    /// <param name="serverName">The server's name, recorded as a container label.</param>
    /// <param name="command">The command to run inside the image.</param>
    /// <param name="arguments">Its arguments.</param>
    /// <param name="environmentNames">
    /// The variables the container gets, by <b>name</b>. Each becomes <c>-e NAME</c>,
    /// which tells the runtime to copy the value from its own environment, so a
    /// secret never appears on a command line that <c>ps</c> can show.
    /// </param>
    /// <remarks>
    /// Docker and Podman accept the same flags here, so one list serves both.
    /// Pure: the same inputs give the same list, which is what makes the
    /// generated command reviewable in a unit test rather than only on a host
    /// with a daemon.
    /// </remarks>
    public IReadOnlyList<string> RunArguments(
        string serverName,
        string command,
        IReadOnlyList<string> arguments,
        IEnumerable<string> environmentNames)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serverName);
        ArgumentException.ThrowIfNullOrWhiteSpace(command);
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(environmentNames);

        List<string> run =
        [
            "run", "-i", "--rm",
            "--label", $"{ServerLabel}={serverName}",
            "--network", Network,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", PidsLimit.ToString(CultureInfo.InvariantCulture),
            "--memory", Memory,
            "--cpus", Cpus.ToString(CultureInfo.InvariantCulture),
            "--user", User,
        ];

        if (ReadOnlyRoot)
        {
            run.Add("--read-only");
        }

        run.AddRange(["--tmpfs", ScratchMount, "-e", "HOME=/tmp"]);

        foreach (var mount in Mounts)
        {
            run.Add("--mount");
            run.Add($"type=bind,source={mount.HostPath},target={mount.ContainerPath}" +
                    (mount.Mode is MountMode.ReadOnly ? ",readonly=true" : string.Empty));
        }

        foreach (var name in environmentNames.Order(StringComparer.Ordinal))
        {
            run.AddRange(["-e", name]);
        }

        run.Add(Image);
        run.Add(command);
        run.AddRange(arguments);
        return run;
    }

    /// <summary>
    /// What the server can reach, in one line: for <c>validate</c>, so a reviewer
    /// sees the boundary without reading the generated command.
    /// </summary>
    public string Describe()
    {
        var mounts = Mounts.Count == 0
            ? "no host files"
            : string.Join(", ", Mounts.Select(m =>
                $"{m.HostPath} as {m.ContainerPath} ({(m.Mode is MountMode.ReadOnly ? "read-only" : "read-write")})"));

        return $"{Executable} container from {Image}; network {Network}; {mounts}; " +
               $"root filesystem {(ReadOnlyRoot ? "read-only" : "writable")}; user {User}; " +
               $"memory {Memory}, {Cpus.ToString(CultureInfo.InvariantCulture)} CPU, {PidsLimit} processes";
    }
}
