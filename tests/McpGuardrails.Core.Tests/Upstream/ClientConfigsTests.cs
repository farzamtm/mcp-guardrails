using System.Text;
using System.Text.Json.Nodes;
using McpGuardrails.Core.Tests.Scanners;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Tests.Upstream;

/// <summary>
/// Import and wrap for each client format, with samples shaped like the configs
/// people actually have.
/// </summary>
public sealed class ClientConfigsTests
{
    private static ClientApp Client(string name) => ClientConfigs.Find(name)!;

    private static readonly string _projectDirectory = FakeHost.At("work", "project");

    /// <summary>Imports, then loads the result as a servers file with the lifted secrets set.</summary>
    private static (ImportResult Import, ServersLoadResult Loaded) RoundTrip(string client, string config, string? path = null)
    {
        var host = new FakeHost();
        var result = ClientConfigs.Import(Client(client), config, path ?? Path.Combine(_projectDirectory, ".mcp.json"), host.Build());

        foreach (var secret in result.Secrets)
        {
            host.Variables[secret.Variable] = secret.Value;
        }

        return (result, ServersLoader.Parse(result.ServersYaml, _projectDirectory, host.Build()));
    }

    [Fact]
    public void Import_ClaudeDesktop_LiftsSecretsOutOfTheFile()
    {
        var token = SecretSamples.GitHubToken;
        var config = $$"""
            {
              "mcpServers": {
                "filesystem": {
                  "command": "npx",
                  "args": ["-y", "@modelcontextprotocol/server-filesystem@2026.8.31", "/Users/me/Desktop"]
                },
                "github": {
                  "command": "docker",
                  "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"],
                  "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "{{token}}", "LOG_LEVEL": "info" }
                }
              },
              "globalShortcut": "Ctrl+Space"
            }
            """;

        var (import, loaded) = RoundTrip("claude-desktop", config);

        // The acceptance criterion: no secret value in the servers file.
        Assert.DoesNotContain(token, import.ServersYaml, StringComparison.Ordinal);
        var secret = Assert.Single(import.Secrets);
        Assert.Equal("GITHUB_GITHUB_PERSONAL_ACCESS_TOKEN", secret.Variable);
        Assert.Equal(token, secret.Value);
        Assert.Equal("github", secret.Server);
        Assert.Equal("env.GITHUB_PERSONAL_ACCESS_TOKEN", secret.Field);

        Assert.True(loaded.IsValid, string.Join("\n", loaded.Errors));
        Assert.Equal(2, import.ServerCount);
        var github = loaded.Servers.Single(s => s.Name == "github");
        Assert.Equal(token, github.EnvironmentVariables!["GITHUB_PERSONAL_ACCESS_TOKEN"]);
        Assert.Equal("info", github.EnvironmentVariables["LOG_LEVEL"]);
    }

    [Fact]
    public void Import_ClaudeCode_KeepsExistingReferencesAndMapsTypes()
    {
        var config = """
            {
              "mcpServers": {
                "api": {
                  "type": "streamable-http",
                  "url": "${API_BASE_URL:-https://api.example.com}/mcp",
                  "headers": { "Authorization": "Bearer ${API_KEY}" },
                  "headersHelper": "get-headers.sh",
                  "oauth": { "clientId": "x" }
                },
                "old": { "type": "sse", "url": "https://old.example.com/sse" },
                "local": { "type": "stdio", "command": "python3", "args": ["${CLAUDE_PROJECT_DIR:-.}/server.py"] }
              }
            }
            """;

        var host = new FakeHost();
        host.Variables["API_KEY"] = "k";
        var import = ClientConfigs.Import(Client("claude-code"), config, Path.Combine(_projectDirectory, ".mcp.json"), host.Build());
        var loaded = ServersLoader.Parse(import.ServersYaml, _projectDirectory, host.Build());

        Assert.True(loaded.IsValid, string.Join("\n", loaded.Errors));
        Assert.Empty(import.Secrets);
        Assert.Contains("\"Bearer ${API_KEY}\"", import.ServersYaml, StringComparison.Ordinal);

        var api = loaded.Servers.Single(s => s.Name == "api");
        Assert.Equal(UpstreamTransport.Http, api.Transport);
        Assert.Equal(new Uri("https://api.example.com/mcp"), api.Url);
        Assert.Equal(UpstreamTransport.Sse, loaded.Servers.Single(s => s.Name == "old").Transport);
        Assert.Equal("./server.py", loaded.Servers.Single(s => s.Name == "local").Arguments[0]);
        Assert.Contains(import.Notes, n => n.Contains("'headersHelper', 'oauth'", StringComparison.Ordinal));
    }

    [Fact]
    public void Import_Cursor_TranslatesItsVariablesAndBareUrls()
    {
        var path = Path.Combine(_projectDirectory, ".cursor", "mcp.json");
        var config = """
            {
              "mcpServers": {
                "tools": {
                  "type": "stdio",
                  "command": "python3",
                  "args": ["${workspaceFolder}${/}tools${pathSeparator}server.py", "${workspaceFolderBasename}"],
                  "env": { "API_KEY": "${env:MY_KEY}", "CACHE": "${userHome}/.cache" },
                  "envFile": "${workspaceFolder}/.env"
                },
                "remote": { "url": "https://remote.example.com/mcp", "headers": { "X-Api-Key": "plain-value-123" } }
              }
            }
            """;

        var host = new FakeHost();
        host.Variables["MY_KEY"] = "k";
        host.Contents[Path.Combine(_projectDirectory, ".env")] = "A=1";
        var import = ClientConfigs.Import(Client("cursor"), config, path, host.Build());
        foreach (var secret in import.Secrets)
        {
            host.Variables[secret.Variable] = secret.Value;
        }

        var loaded = ServersLoader.Parse(import.ServersYaml, _projectDirectory, host.Build());

        Assert.True(loaded.IsValid, string.Join("\n", loaded.Errors));
        var tools = loaded.Servers.Single(s => s.Name == "tools");
        var separator = OperatingSystem.IsWindows() ? "\\" : "/";
        Assert.Equal($"{_projectDirectory}{separator}tools{separator}server.py", tools.Arguments[0]);
        Assert.Equal("project", tools.Arguments[1]);
        Assert.Equal("k", tools.EnvironmentVariables!["API_KEY"]);
        Assert.Equal($"{FakeHost.Home}/.cache", tools.EnvironmentVariables["CACHE"]);
        Assert.Equal("1", tools.EnvironmentVariables["A"]);

        // A header named like a key is lifted even though its value has no
        // recognisable shape.
        var secretHeader = Assert.Single(import.Secrets);
        Assert.Equal("REMOTE_X_API_KEY", secretHeader.Variable);
        Assert.Equal(UpstreamTransport.Http, loaded.Servers.Single(s => s.Name == "remote").Transport);
        Assert.Contains(import.Notes, n => n.Contains("imported as Streamable HTTP", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(true, "a\\b")]
    [InlineData(false, "a/b")]
    public void Import_UsesThePlatformsPathSeparator(bool windows, string expected)
    {
        var config = """{ "mcpServers": { "a": { "type": "stdio", "command": "npx", "args": ["a${/}b"] } } }""";

        var import = ClientConfigs.Import(Client("cursor"), config, "mcp.json", new FakeHost { IsWindows = windows }.Build());

        Assert.Contains(ClientConfigs.Quote(expected), import.ServersYaml, StringComparison.Ordinal);
    }

    [Fact]
    public void Import_VsCode_ReadsServersWithCommentsAndInputs()
    {
        var path = Path.Combine(_projectDirectory, ".vscode", "mcp.json");
        var config = """
            {
              // VS Code allows comments and trailing commas.
              "inputs": [{ "type": "promptString", "id": "api-token", "password": true }],
              "servers": {
                "Perplexity Search": {
                  "type": "stdio",
                  "command": "npx",
                  "args": ["-y", "server-perplexity-ask"],
                  "env": { "PERPLEXITY_API_KEY": "${input:api-token}", "MODE": 2, "FLAG": true, "GONE": null },
                  "cwd": "${workspaceFolder}",
                  "dev": { "watch": "src/**" },
                  "disabled": true,
                },
              },
            }
            """;

        var import = ClientConfigs.Import(Client("vscode"), config, path, new FakeHost().Build());

        Assert.Contains("  Perplexity-Search:\n", import.ServersYaml, StringComparison.Ordinal);
        Assert.Contains("\"PERPLEXITY_API_KEY\": \"${API_TOKEN}\"", import.ServersYaml, StringComparison.Ordinal);
        Assert.Contains("\"MODE\": \"2\"", import.ServersYaml, StringComparison.Ordinal);
        Assert.Contains("\"FLAG\": \"true\"", import.ServersYaml, StringComparison.Ordinal);
        Assert.Contains("\"GONE\": null", import.ServersYaml, StringComparison.Ordinal);
        Assert.Contains($"cwd: {ClientConfigs.Quote(_projectDirectory)}", import.ServersYaml, StringComparison.Ordinal);
        Assert.Contains("disabled: true", import.ServersYaml, StringComparison.Ordinal);
        Assert.Contains(import.Notes, n => n.Contains("Renamed server 'Perplexity Search' to 'Perplexity-Search'", StringComparison.Ordinal));
        Assert.Contains(import.Notes, n => n.Contains("Set API_TOKEN", StringComparison.Ordinal));
        Assert.Contains(import.Notes, n => n.Contains("without a pinned version", StringComparison.Ordinal));

        // Disabled, so it loads without API_TOKEN being set.
        var loaded = ServersLoader.Parse(import.ServersYaml, _projectDirectory, new FakeHost().Build());
        Assert.True(loaded.IsValid, string.Join("\n", loaded.Errors));
        Assert.Equal(["Perplexity-Search"], loaded.Disabled);
    }

    [Fact]
    public void Import_EscapesLiteralDollarsAndQuotesEverything()
    {
        var config = """
            { "mcpServers": { "a": {
                "command": "npx",
                "args": ["p@1.0.0", "price$5", "$$", "a$${B}", "line\nbreak\ttab\r\"q\"\\", "\u0001", null, 7]
            } } }
            """;

        var host = new FakeHost();
        host.Variables["B"] = "b";
        var import = ClientConfigs.Import(Client("claude-desktop"), config, Path.Combine(_projectDirectory, "c.json"), host.Build());
        var server = Assert.Single(ServersLoader.Parse(import.ServersYaml, _projectDirectory, host.Build()).Servers);

        // Every value round-trips to exactly what the client would have passed.
        Assert.Equal(["p@1.0.0", "price$5", "$$", "a$b", "line\nbreak\ttab\r\"q\"\\", "\u0001", "", "7"], server.Arguments);
    }

    [Fact]
    public void Import_RenamesCollidingAndUnusableNames()
    {
        var config = """{ "mcpServers": { "my_server": {"command":"npx"}, "my-server": {"command":"npx"}, "__": {"command":"npx"}, "bad": 5 } }""";

        var import = ClientConfigs.Import(Client("claude-desktop"), config, "c.json", new FakeHost().Build());

        Assert.Contains("  my-server:\n", import.ServersYaml, StringComparison.Ordinal);
        Assert.Contains("  my-server-2:\n", import.ServersYaml, StringComparison.Ordinal);
        Assert.Contains("  server:\n", import.ServersYaml, StringComparison.Ordinal);
        Assert.Contains(import.Notes, n => n.Contains("Skipped server 'bad'", StringComparison.Ordinal));
        Assert.Equal(3, import.ServerCount);
    }

    [Fact]
    public void Import_GivesEachLiftedSecretItsOwnVariable()
    {
        var config = """{ "mcpServers": { "a": { "command": "npx", "args": ["--key", "x"], "env": { "A_KEY": "one" }, "headers": { "a-key": "two" } } } }""";

        var import = ClientConfigs.Import(Client("claude-desktop"), config, "c.json", new FakeHost().Build());

        Assert.Equal(["A_A_KEY", "A_A_KEY_2"], import.Secrets.Select(s => s.Variable));
    }

    [Fact]
    public void Import_LiftsASecretFromArgsAndUrl()
    {
        var token = SecretSamples.GitHubToken;
        var config = $$"""{ "mcpServers": { "a": { "command": "npx", "args": ["p@1.0.0", "{{token}}"] }, "b": { "type": "http", "url": "https://x.example/mcp?token={{token}}", "args": [], "env": { "OBJ": { "a": 1 } } } } }""";

        var import = ClientConfigs.Import(Client("claude-desktop"), config, "c.json", new FakeHost().Build());

        Assert.DoesNotContain(token, import.ServersYaml, StringComparison.Ordinal);
        Assert.Equal(["A_ARGS_1_", "B_URL"], import.Secrets.Select(s => s.Variable));
        Assert.Contains("\"OBJ\": \"{\\\"a\\\":1}\"", import.ServersYaml, StringComparison.Ordinal);
    }

    [Fact]
    public void Import_AcceptsAConfigWithNoServers()
    {
        var import = ClientConfigs.Import(Client("cursor"), "{}", "c.json", new FakeHost().Build());

        Assert.Equal(0, import.ServerCount);
        Assert.Contains("servers: {}", import.ServersYaml, StringComparison.Ordinal);
        Assert.True(ServersLoader.Parse(import.ServersYaml, _projectDirectory, new FakeHost().Build()).IsValid);
    }

    [Theory]
    [InlineData("not json", "not valid JSON")]
    [InlineData("[1]", "not a JSON object")]
    [InlineData("""{ "mcpServers": [] }""", "is not an object")]
    public void Import_RefusesAConfigItCannotRead(string config, string expected) =>
        Assert.Contains(
            expected,
            Assert.Throws<ClientConfigException>(() => ClientConfigs.Import(Client("claude-desktop"), config, "c.json", new FakeHost().Build())).Message,
            StringComparison.Ordinal);

    [Fact]
    public void Import_HandlesUnterminatedInputs()
    {
        var config = """{ "servers": { "a": { "type": "stdio", "command": "npx", "env": { "T": "${input:x" } } } }""";

        var import = ClientConfigs.Import(Client("vscode"), config, "mcp.json", new FakeHost().Build());

        Assert.Contains("\"T\": \"${input:x\"", import.ServersYaml, StringComparison.Ordinal);
    }

    [Fact]
    public void Import_RejectsNullArguments()
    {
        var host = new FakeHost().Build();
        var client = Client("cursor");

        Assert.Throws<ArgumentNullException>(() => ClientConfigs.Import(null!, "{}", "p", host));
        Assert.Throws<ArgumentNullException>(() => ClientConfigs.Import(client, null!, "p", host));
        Assert.Throws<ArgumentNullException>(() => ClientConfigs.Import(client, "{}", null!, host));
        Assert.Throws<ArgumentNullException>(() => ClientConfigs.Import(client, "{}", "p", null!));
    }

    // ------------------------------------------------------------------- wrap

    private const string _desktopConfig = """
        {
          "mcpServers": {
            "fs": { "command": "npx", "args": ["-y", "pkg@1.0.0"] }
          },
          "preferences": { "theme": "dark" }
        }
        """;

    [Theory]
    [InlineData("claude-desktop", "mcpServers", false)]
    [InlineData("cursor", "mcpServers", true)]
    [InlineData("vscode", "servers", true)]
    public void Wrap_ReplacesTheServerListWithTheProxyAndKeepsTheRest(string name, string key, bool typed)
    {
        var client = Client(name);
        var config = _desktopConfig.Replace("mcpServers", key, StringComparison.Ordinal);
        LiftedSecret[] secrets = [new("FS_TOKEN", "s3cret", "fs", "env.TOKEN")];

        var wrapped = JsonNode.Parse(ClientConfigs.Wrap(client, config, "c.json", "/bin/mcp-guardrails", "/s.yaml", "/p.yaml", secrets))!;

        var servers = wrapped[key]!.AsObject();
        var entry = Assert.Single(servers).Value!;
        Assert.Equal(ClientConfigs.WrappedEntryName, servers.Single().Key);
        Assert.Equal("/bin/mcp-guardrails", (string?)entry["command"]);
        Assert.Empty(entry["args"]!.AsArray());
        Assert.Equal("/s.yaml", (string?)entry["env"]![ServersLoader.FileVariable]);
        Assert.Equal("/p.yaml", (string?)entry["env"]!["GUARDRAILS_POLICY"]);
        Assert.Equal("s3cret", (string?)entry["env"]!["FS_TOKEN"]);
        Assert.Equal(typed ? "stdio" : null, (string?)entry["type"]);
        Assert.Equal("dark", (string?)wrapped["preferences"]!["theme"]);
    }

    [Theory]
    [InlineData("{}", "nothing to wrap")]
    [InlineData("""{ "mcpServers": {} }""", "nothing to wrap")]
    [InlineData("""{ "mcpServers": { "guardrails": { "command": "x" } } }""", "already has a 'guardrails' server")]
    public void Wrap_RefusesAConfigItShouldNotChange(string config, string expected) =>
        Assert.Contains(
            expected,
            Assert.Throws<ClientConfigException>(() =>
                ClientConfigs.Wrap(Client("claude-desktop"), config, "c.json", "b", "s", "p", [])).Message,
            StringComparison.Ordinal);

    [Fact]
    public void Wrap_RefusesClaudeCodesStateFile() =>
        Assert.Contains(
            "cannot be wrapped",
            Assert.Throws<ClientConfigException>(() =>
                ClientConfigs.Wrap(Client("claude-code"), _desktopConfig, Path.Combine(FakeHost.Home, ".claude.json"), "b", "s", "p", [])).Message,
            StringComparison.Ordinal);

    [Fact]
    public void Wrap_RejectsNullArguments()
    {
        var client = Client("cursor");

        Assert.Throws<ArgumentNullException>(() => ClientConfigs.Wrap(null!, "{}", "p", "b", "s", "p", []));
        Assert.Throws<ArgumentNullException>(() => ClientConfigs.Wrap(client, null!, "p", "b", "s", "p", []));
        Assert.Throws<ArgumentNullException>(() => ClientConfigs.Wrap(client, "{}", null!, "b", "s", "p", []));
        Assert.Throws<ArgumentNullException>(() => ClientConfigs.Wrap(client, "{}", "p", "b", "s", "p", null!));
    }

    // --------------------------------------------------------- the client table

    [Theory]
    [InlineData(true, false, "Claude", "claude_desktop_config.json")]
    [InlineData(false, true, "Claude", "claude_desktop_config.json")]
    public void DefaultPaths_ClaudeDesktopPerPlatform(bool windows, bool mac, string folder, string file)
    {
        var host = new FakeHost { IsWindows = windows, IsMacOS = mac };
        host.Variables["APPDATA"] = FakeHost.At("AppData");

        var path = Assert.Single(ClientConfigs.DefaultPaths(Client("claude-desktop"), host.Build(), _projectDirectory));

        Assert.EndsWith(Path.Combine(folder, file), path, StringComparison.Ordinal);
        Assert.StartsWith(windows ? FakeHost.At("AppData") : Path.Combine(FakeHost.Home, "Library", "Application Support"), path, StringComparison.Ordinal);
    }

    [Fact]
    public void DefaultPaths_ClaudeDesktopHasNoLinuxBuild() =>
        Assert.Empty(ClientConfigs.DefaultPaths(Client("claude-desktop"), new FakeHost { IsWindows = false }.Build(), _projectDirectory));

    [Fact]
    public void DefaultPaths_ProjectFilesComeBeforeUserFiles()
    {
        var linux = new FakeHost { IsWindows = false }.Build();
        var windows = new FakeHost { IsWindows = true }.Build(); // no APPDATA: falls back under the profile

        Assert.Equal(
            [Path.Combine(_projectDirectory, ".mcp.json"), Path.Combine(FakeHost.Home, ".claude.json")],
            ClientConfigs.DefaultPaths(Client("claude-code"), linux, _projectDirectory));
        Assert.Equal(
            [Path.Combine(_projectDirectory, ".cursor", "mcp.json"), Path.Combine(FakeHost.Home, ".cursor", "mcp.json")],
            ClientConfigs.DefaultPaths(Client("cursor"), linux, _projectDirectory));
        Assert.Equal(
            [Path.Combine(_projectDirectory, ".vscode", "mcp.json"), Path.Combine(FakeHost.Home, ".config", "Code", "User", "mcp.json")],
            ClientConfigs.DefaultPaths(Client("vscode"), linux, _projectDirectory));
        Assert.Equal(
            Path.Combine(FakeHost.Home, "AppData", "Roaming", "Code", "User", "mcp.json"),
            ClientConfigs.DefaultPaths(Client("vscode"), windows, _projectDirectory)[1]);
    }

    [Fact]
    public void DefaultPaths_RejectsNullArguments()
    {
        var host = new FakeHost().Build();

        Assert.Throws<ArgumentNullException>(() => ClientConfigs.DefaultPaths(null!, host, "w"));
        Assert.Throws<ArgumentNullException>(() => ClientConfigs.DefaultPaths(Client("cursor"), null!, "w"));
        Assert.Throws<ArgumentNullException>(() => ClientConfigs.DefaultPaths(Client("cursor"), host, null!));
    }

    [Fact]
    public void Find_KnowsEveryClientByItsCommandLineName()
    {
        Assert.Equal(["claude-desktop", "claude-code", "cursor", "vscode"], ClientConfigs.All.Select(c => c.Name));
        Assert.Null(ClientConfigs.Find("windsurf"));
    }

    [Theory]
    [InlineData("my_server", "my-server")]
    [InlineData("a  b", "a-b")]
    [InlineData("-x-", "x")]
    [InlineData("___", "server")]
    [InlineData("ünï", "n")]
    public void SanitizeName_KeepsOnlyLegalCharacters(string name, string expected) =>
        Assert.Equal(expected, ClientConfigs.SanitizeName(name));

    [Theory]
    [InlineData("github-token", "GITHUB_TOKEN")]
    [InlineData("1x", "_1X")]
    [InlineData("", "_")]
    public void VariableName_IsAnEnvironmentVariableName(string text, string expected) =>
        Assert.Equal(expected, ClientConfigs.VariableName(text));

    [Theory]
    [InlineData("GITHUB_TOKEN", true)]
    [InlineData("X-Api-Key", true)]
    [InlineData("DB_PASSWORD", true)]
    [InlineData("KEYBOARD", false)]
    [InlineData("LOG_LEVEL", false)]
    [InlineData(null, false)]
    public void IsSensitiveKey_RecognisesCredentialNames(string? key, bool expected) =>
        Assert.Equal(expected, ClientConfigs.IsSensitiveKey(key));

    [Fact]
    public void WriteJson_IsIndentedAndReadable()
    {
        var json = ClientConfigs.WriteJson(new JsonObject { ["url"] = "https://x.example/?a=1&b=2" });

        Assert.Equal("{\n  \"url\": \"https://x.example/?a=1&b=2\"\n}\n", json.ReplaceLineEndings("\n"));
        Assert.Equal(json, Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(json)));
    }
}

public sealed class LineDiffTests
{
    [Fact]
    public void Format_MarksRemovedAddedAndKeptLines() =>
        Assert.Equal(
            "  a\n- b\n+ B\n  c\n+ d\n",
            LineDiff.Format("a\nb\nc\n", "a\nB\nc\nd"));

    [Fact]
    public void Format_HandlesEmptyTexts()
    {
        Assert.Equal("+ x\n", LineDiff.Format("", "x"));
        Assert.Equal("- x\n", LineDiff.Format("x\r\n", ""));
        Assert.Equal("", LineDiff.Format("", ""));
    }

    [Fact]
    public void Format_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => LineDiff.Format(null!, ""));
        Assert.Throws<ArgumentNullException>(() => LineDiff.Format("", null!));
    }
}
