using System.Text.Json;
using McpGuardrails.Core.Scanners;

namespace McpGuardrails.Core.Tests.Scanners;

/// <summary>
/// The walk over a call's arguments: which strings each detector reads, where a
/// hit is reported, and what happens at the caps.
/// </summary>
public sealed class ArgumentScannerTests
{
    private static Dictionary<string, JsonElement> Args(string json)
    {
        using var document = JsonDocument.Parse(json);

        return document.RootElement.EnumerateObject()
            .ToDictionary(property => property.Name, property => property.Value.Clone(), StringComparer.Ordinal);
    }

    private static ArgumentFindings Scan(string json, string tool = "web__fetch", ArgumentDetectors detectors = ArgumentDetectors.All) =>
        ArgumentScanner.Scan(tool, Args(json), detectors);

    [Fact]
    public void CleanArguments_HaveNoFindings()
    {
        var findings = Scan("""{"url": "https://example.com", "path": "src/main.cs", "count": 3, "on": true, "x": null}""");

        Assert.True(findings.IsClean);
        Assert.Same(ArgumentFindings.Clean, findings);
        Assert.Empty(findings.Detectors);
        Assert.Equal("", findings.Summary);
    }

    [Fact]
    public void NoArgumentsOrNoDetectors_ScanNothing()
    {
        Assert.Same(ArgumentFindings.Clean, ArgumentScanner.Scan("t", null, ArgumentDetectors.All));
        Assert.Same(ArgumentFindings.Clean, ArgumentScanner.Scan("t", Args("""{"u": "http://localhost"}"""), ArgumentDetectors.None));
        Assert.Throws<ArgumentNullException>(() => ArgumentScanner.Scan(null!, null, ArgumentDetectors.All));
    }

    [Fact]
    public void Hits_NameTheArgumentWhereTheyWereFound_NestedAndInArrays()
    {
        var findings = Scan("""
            {
              "request": { "targets": ["https://example.com", "http://169.254.169.254/"] },
              "file": "../../etc/hosts",
              "keyPath": "/home/u/.ssh/id_rsa"
            }
            """);

        Assert.Equal(["ssrf", "sensitive-path", "path-traversal"], findings.Detectors);
        Assert.Equal(
            "ssrf in 'request.targets[1]', sensitive-path in 'keyPath', path-traversal in 'file'",
            findings.Summary);
    }

    [Fact]
    public void EachDetector_ReportsOnlyItsFirstHit()
    {
        var findings = Scan("""{"urls": ["http://localhost", "http://10.0.0.1", "http://127.0.0.1"]}""");

        var hit = Assert.Single(findings.Hits);
        Assert.Equal(new ArgumentHit("ssrf", "urls[0]"), hit);
    }

    [Fact]
    public void OnlyTheChosenDetectors_Run()
    {
        const string json = """{"u": "http://localhost", "p": "../x"}""";

        Assert.Equal(["path-traversal"], Scan(json, detectors: ArgumentDetectors.PathTraversal).Detectors);
        Assert.Equal(["ssrf"], Scan(json, detectors: ArgumentDetectors.Ssrf).Detectors);
        Assert.True(Scan("""{"p": "~/.ssh/id_rsa"}""", detectors: ArgumentDetectors.Ssrf).IsClean);
        Assert.True(Scan("""{"command": "a; b"}""", detectors: ArgumentDetectors.Ssrf).IsClean);
    }

    [Theory]
    [InlineData("command")]
    [InlineData("cmd")]
    [InlineData("script")]
    [InlineData("shell")]
    [InlineData("exec")]
    [InlineData("args")]
    [InlineData("argv")]
    [InlineData("commands")]
    [InlineData("shell_command")]
    [InlineData("commandLine")]
    [InlineData("pre-script")]
    [InlineData("Command")]
    public void ShellMetachar_ReadsArgumentsNamedLikeCommands(string name)
    {
        var findings = Scan($$"""{"{{name}}": "ls; rm -rf /"}""", tool: "build__run");

        Assert.Equal(["shell-metachar"], findings.Detectors);
    }

    [Theory]
    [InlineData("description")]
    [InlineData("body")]
    [InlineData("commander")]
    [InlineData("")]
    [InlineData("__")]
    public void ShellMetachar_IgnoresProseArguments(string name)
    {
        Assert.True(Scan($$"""{"{{name}}": "Tom & Jerry; a | b > c"}""", tool: "notes__create").IsClean);
    }

    [Fact]
    public void ShellMetachar_ReadsEveryStringOfAShellTool_AndNestedCommandValues()
    {
        Assert.Equal(["shell-metachar"], Scan("""{"input": "a && b"}""", tool: "box__exec").Detectors);
        Assert.Equal(["shell-metachar"], Scan("""{"input": "a && b"}""", tool: "Terminal__Shell").Detectors);
        Assert.Equal(["shell-metachar"], Scan("""{"input": "a && b"}""", tool: "x__run_command").Detectors);

        // Under a command, a nested name that says nothing does not turn it off.
        Assert.Equal(
            "shell-metachar in 'command.parts[1]'",
            Scan("""{"command": {"parts": ["ls", "x`id`"]}}""", tool: "ci__job").Summary);
    }

    [Theory]
    [InlineData("a;b")]
    [InlineData("a|b")]
    [InlineData("a&b")]
    [InlineData("a`b`")]
    [InlineData("a>b")]
    [InlineData("a<b")]
    [InlineData("a\nb")]
    [InlineData("a\rb")]
    [InlineData("$(id)")]
    [InlineData("${HOME}")]
    public void ShellMetacharacters_AreRecognised(string value) =>
        Assert.True(ArgumentScanner.HasShellMetacharacters(value));

    [Theory]
    [InlineData("")]
    [InlineData("ls -la /tmp")]
    [InlineData("echo $HOME")]
    [InlineData("cost: $")]
    [InlineData("(a) [b] {c}")]
    public void OrdinaryCommands_HaveNoMetacharacters(string value) =>
        Assert.False(ArgumentScanner.HasShellMetacharacters(value));

    [Fact]
    public void SensitivePath_ReadsAPathNamedArgument_WithSpaces_AsOnePath()
    {
        Assert.Equal(["sensitive-path"], Scan("""{"filePaths": ["My Keys/id_rsa"]}""").Detectors);
        Assert.True(Scan("""{"note": "My Keys/id_rsa.pub and more"}""").IsClean);
        Assert.Equal(["sensitive-path"], Scan("""{"destination": ".env"}""").Detectors);
        Assert.True(Scan("""{"note": "add .env to .gitignore"}""").IsClean);
    }

    [Fact]
    public void ArgumentPaths_AreTruncated()
    {
        var name = new string('k', 200);
        var findings = Scan($$"""{"{{name}}": "http://localhost"}""");

        var hit = Assert.Single(findings.Hits);
        Assert.Equal(new string('k', 80) + "…", hit.Argument);
    }

    [Fact]
    public void NestingDeeperThanTheCap_IsAFinding()
    {
        var deep = string.Concat(Enumerable.Repeat("[", ArgumentScanner.MaxDepth)) + "\"x\"" +
                   string.Concat(Enumerable.Repeat("]", ArgumentScanner.MaxDepth));
        using var document = JsonDocument.Parse(deep, new JsonDocumentOptions { MaxDepth = 256 });
        var arguments = new Dictionary<string, JsonElement> { ["a"] = document.RootElement };

        var findings = ArgumentScanner.Scan("t", arguments, ArgumentDetectors.All);

        Assert.Equal([new ArgumentHit("argument-too-large", "")], findings.Hits);
        Assert.Equal("argument-too-large", findings.Summary);
    }

    [Fact]
    public void NestingAtTheCap_IsScanned()
    {
        var nested = string.Concat(Enumerable.Repeat("[", ArgumentScanner.MaxDepth - 1)) + "\"http://localhost\"" +
                     string.Concat(Enumerable.Repeat("]", ArgumentScanner.MaxDepth - 1));
        using var document = JsonDocument.Parse(nested, new JsonDocumentOptions { MaxDepth = 256 });

        var findings = ArgumentScanner.Scan("t", new Dictionary<string, JsonElement> { ["a"] = document.RootElement }, ArgumentDetectors.All);

        Assert.Equal(["ssrf"], findings.Detectors);
    }

    [Fact]
    public void MoreCharactersThanTheCap_IsAFinding_AndHitsBeforeItAreKept()
    {
        var padding = new string('a', ArgumentScanner.MaxCharacters);
        var arguments = Args($$"""{"url": "http://localhost", "pad": "{{padding}}", "later": "../x"}""");

        var findings = ArgumentScanner.Scan("t", arguments, ArgumentDetectors.All);

        // The URL came first and was read; the padding broke the cap, so the
        // traversal after it was never reached - and the call says so.
        Assert.Equal(["ssrf", "argument-too-large"], findings.Detectors);
    }

    [Fact]
    public void AHugeKey_CountsAgainstTheCap()
    {
        var key = new string('k', ArgumentScanner.MaxCharacters + 1);
        var arguments = new Dictionary<string, JsonElement> { [key] = JsonDocument.Parse("1").RootElement };

        Assert.Equal(["argument-too-large"], ArgumentScanner.Scan("t", arguments, ArgumentDetectors.All).Detectors);
    }

    [Fact]
    public void MoreValuesThanTheCap_IsAFinding()
    {
        var array = "[" + string.Join(",", Enumerable.Repeat("0", ArgumentScanner.MaxValues)) + "]";
        var objects = "{\"o\": {" + string.Join(",", Enumerable.Range(0, ArgumentScanner.MaxValues / 2 + 1).Select(i => $"\"k{i}\":0")) + "}}";

        Assert.Equal(["argument-too-large"], Scan($$"""{"a": {{array}}}""").Detectors);
        Assert.Equal(["argument-too-large"], Scan(objects).Detectors);
    }

    [Fact]
    public void ATenMegabyteArgument_IsScannedInFull_InLinearTime()
    {
        // The shape of a large file write: mostly ordinary text, a URL at the end.
        var content = string.Concat(Enumerable.Repeat("Lorem ipsum dolor sit amet, see ./docs/a.md: ok. ", 210_000)) +
                      "http://169.254.169.254/";
        Assert.True(content.Length > 10_000_000);
        var arguments = Args($$"""{"content": "{{content}}"}""");

        var started = System.Diagnostics.Stopwatch.StartNew();
        var findings = ArgumentScanner.Scan("fs__write_file", arguments, ArgumentDetectors.All);

        Assert.Equal(["ssrf"], findings.Detectors);
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(10), $"took {started.Elapsed}");
    }
}
