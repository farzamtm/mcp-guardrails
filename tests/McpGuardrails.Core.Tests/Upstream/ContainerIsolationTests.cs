using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Tests.Upstream;

/// <summary>
/// The generated container command, compared whole against golden argument
/// lists: a flag dropped or reordered here is a hole in the isolation that no
/// other test would see, because the runtime would still start the server.
/// </summary>
public sealed class ContainerIsolationTests
{
    private const string _image = "python:3.13-alpine@sha256:abc";

    private static readonly string[] _strictPrefix =
    [
        "run", "-i", "--rm",
        "--label", "mcp-guardrails.server=fetch",
        "--network", "none",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "256",
        "--memory", "512m",
        "--cpus", "1",
        "--user", "65534:65534",
        "--read-only",
        "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m",
        "-e", "HOME=/tmp",
    ];

    [Theory]
    [InlineData(ContainerRuntime.Docker, "docker")]
    [InlineData(ContainerRuntime.Podman, "podman")]
    public void Defaults_AreStrict_ForEveryRuntime(ContainerRuntime runtime, string executable)
    {
        var isolation = new ContainerIsolation { Runtime = runtime, Image = _image };

        var arguments = isolation.RunArguments("fetch", "uvx", ["mcp-server-fetch==2025.4.7"], []);

        Assert.Equal(executable, isolation.Executable);
        Assert.Equal([.. _strictPrefix, _image, "uvx", "mcp-server-fetch==2025.4.7"], arguments);
    }

    [Fact]
    public void EveryOption_IsRendered_InAFixedOrder()
    {
        var isolation = new ContainerIsolation
        {
            Runtime = ContainerRuntime.Docker,
            Image = _image,
            Network = "bridge",
            Mounts =
            [
                new ContainerMount("/srv/data", "/workspace", MountMode.ReadWrite),
                new ContainerMount("/srv/config.json", "/etc/app.json", MountMode.ReadOnly),
            ],
            ReadOnlyRoot = false,
            Memory = "2g",
            Cpus = 0.5,
            PidsLimit = 64,
            User = "1000:1000",
        };

        var arguments = isolation.RunArguments("fs", "node", ["server.js", "--root", "/workspace"], ["TOKEN", "API_KEY"]);

        Assert.Equal(
            [
                "run", "-i", "--rm",
                "--label", "mcp-guardrails.server=fs",
                "--network", "bridge",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--pids-limit", "64",
                "--memory", "2g",
                "--cpus", "0.5",
                "--user", "1000:1000",
                "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m",
                "-e", "HOME=/tmp",
                "--mount", "type=bind,source=/srv/data,target=/workspace",
                "--mount", "type=bind,source=/srv/config.json,target=/etc/app.json,readonly=true",
                // Sorted, so the command (and the pins identity built from it)
                // does not change with the order of the env block.
                "-e", "API_KEY",
                "-e", "TOKEN",
                _image, "node", "server.js", "--root", "/workspace",
            ],
            arguments);
    }

    [Fact]
    public void Environment_IsPassedByName_NeverByValue()
    {
        var isolation = new ContainerIsolation { Runtime = ContainerRuntime.Docker, Image = _image };

        var arguments = isolation.RunArguments("gh", "server", [], ["GITHUB_TOKEN"]);

        var index = arguments.ToList().IndexOf("GITHUB_TOKEN");
        Assert.Equal("-e", arguments[index - 1]);
        Assert.DoesNotContain(arguments, a => a.StartsWith("GITHUB_TOKEN=", StringComparison.Ordinal));
    }

    [Fact]
    public void Image_ComesAfterEveryFlag_SoTheServersArgumentsCannotBecomeRuntimeFlags()
    {
        var isolation = new ContainerIsolation { Runtime = ContainerRuntime.Docker, Image = _image };

        var arguments = isolation.RunArguments("x", "--privileged", ["--network", "host"], []);

        Assert.Equal([_image, "--privileged", "--network", "host"], arguments.TakeLast(4));
        Assert.Equal(["none"], arguments.Take(arguments.Count - 4).SkipWhile(a => a != "--network").Skip(1).Take(1));
    }

    [Fact]
    public void RunArguments_RejectsMissingInputs()
    {
        var isolation = new ContainerIsolation { Runtime = ContainerRuntime.Docker, Image = _image };

        Assert.Throws<ArgumentException>(() => isolation.RunArguments(" ", "cmd", [], []));
        Assert.Throws<ArgumentException>(() => isolation.RunArguments("s", "", [], []));
        Assert.Throws<ArgumentNullException>(() => isolation.RunArguments("s", "cmd", null!, []));
        Assert.Throws<ArgumentNullException>(() => isolation.RunArguments("s", "cmd", [], null!));
    }

    [Fact]
    public void Describe_SaysWhatTheServerCanReach()
    {
        var strict = new ContainerIsolation { Runtime = ContainerRuntime.Podman, Image = _image };
        Assert.Equal(
            $"podman container from {_image}; network none; no host files; root filesystem read-only; " +
            "user 65534:65534; memory 512m, 1 CPU, 256 processes",
            strict.Describe());

        var loose = strict with
        {
            Network = "bridge",
            ReadOnlyRoot = false,
            Mounts =
            [
                new ContainerMount("/srv/a", "/a", MountMode.ReadOnly),
                new ContainerMount("/srv/b", "/b", MountMode.ReadWrite),
            ],
        };
        Assert.Contains("network bridge; /srv/a as /a (read-only), /srv/b as /b (read-write); root filesystem writable",
            loose.Describe(), StringComparison.Ordinal);
    }
}
