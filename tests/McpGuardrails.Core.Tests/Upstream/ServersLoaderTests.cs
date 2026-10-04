using System.Text.Json;
using McpGuardrails.Core.Tests.Scanners;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Tests.Upstream;

/// <summary>
/// The servers file: its format, every validation rule and its message, and the
/// environment a child process ends up with.
/// </summary>
public sealed class ServersLoaderTests
{
    private static readonly string _base = FakeHost.At("config");

    private static ServersLoadResult Parse(string yaml, FakeHost? host = null) =>
        ServersLoader.Parse(yaml, _base, (host ?? new FakeHost()).Build());

    private static UpstreamServerConfig Single(string yaml, FakeHost? host = null)
    {
        var result = Parse(yaml, host);
        Assert.True(result.IsValid, string.Join("\n", result.Errors));
        return Assert.Single(result.Servers);
    }

    private static string SingleError(string yaml, FakeHost? host = null)
    {
        var result = Parse(yaml, host);
        Assert.Empty(result.Servers);
        return Assert.Single(result.Errors);
    }

    // ------------------------------------------------------------ the format

    [Fact]
    public void Parse_ReadsStdioAndRemoteServers()
    {
        var host = new FakeHost();
        host.Variables["GITHUB_TOKEN"] = "gh-value";
        host.Variables["DOCS_MCP_TOKEN"] = "docs-value";

        var result = Parse("""
            version: 1
            servers:
              fs:
                command: npx
                args: ["-y", "@modelcontextprotocol/server-filesystem@2026.8.31", "${GUARDRAILS_SANDBOX:-/tmp/sandbox}"]
              github:
                command: docker
                args: ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"]
                env:
                  GITHUB_PERSONAL_ACCESS_TOKEN: ${GITHUB_TOKEN}
                env_isolation: false
              docs:
                type: http
                url: https://mcp.example.com/mcp
                headers:
                  Authorization: "Bearer ${DOCS_MCP_TOKEN}"
              legacy:
                type: sse
                url: http://127.0.0.1:9000/sse
            """, host);

        Assert.True(result.IsValid, string.Join("\n", result.Errors));
        Assert.Equal(["fs", "github", "docs", "legacy"], result.Servers.Select(s => s.Name));

        var fs = result.Servers[0];
        Assert.Equal(UpstreamTransport.Stdio, fs.Transport);
        Assert.Equal("npx", fs.Command);
        Assert.Equal("/tmp/sandbox", fs.Arguments[2]);
        // What is shown keeps the reference, not what it expanded to.
        Assert.Contains("${GUARDRAILS_SANDBOX:-/tmp/sandbox}", fs.DisplayTemplate, StringComparison.Ordinal);

        var github = result.Servers[1];
        Assert.Equal("gh-value", github.EnvironmentVariables!["GITHUB_PERSONAL_ACCESS_TOKEN"]);
        Assert.True(github.InheritEnvironment);

        var docs = result.Servers[2];
        Assert.Equal(UpstreamTransport.Http, docs.Transport);
        Assert.Equal(new Uri("https://mcp.example.com/mcp"), docs.Url);
        Assert.Equal("Bearer docs-value", docs.Headers!["authorization"]);
        Assert.Equal("https://mcp.example.com/mcp", docs.DisplayTemplate);
        Assert.Null(docs.Command);

        Assert.Equal(UpstreamTransport.Sse, result.Servers[3].Transport);
    }

    [Fact]
    public void Parse_ReadsJsonToo()
    {
        // A client config pasted as it is: JSON, mcpServers, and a client-only key.
        var result = Parse("""
            {
              "mcpServers": {
                "fixture": { "command": "python3", "args": ["server.py"], "timeout": 5000 }
              }
            }
            """);

        var server = Assert.Single(result.Servers);
        Assert.Equal(["server.py"], server.Arguments);
        Assert.Contains(result.Warnings, w => w.Contains("'timeout'", StringComparison.Ordinal));
    }

    [Fact]
    public void Parse_AcceptsBothServerSectionsTogether()
    {
        var result = Parse("""
            version: 1
            servers:
              a: { command: npx, args: [pkg@1.0.0] }
            mcpServers:
              b: { command: npx, args: [pkg@1.0.0] }
            """);

        Assert.Equal(["a", "b"], result.Servers.Select(s => s.Name));
    }

    [Fact]
    public void Parse_RefusesTheSameNameInBothSections()
    {
        var error = Assert.Single(Parse("""
            version: 1
            servers:
              a: { command: npx, args: [pkg@1.0.0] }
            mcpServers:
              a: { command: npx, args: [pkg@1.0.0] }
            """).Errors);

        Assert.Contains("both 'servers' and 'mcpServers'", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("# only a comment\n")]
    public void Parse_TreatsAnEmptyFileAsNoServers(string yaml)
    {
        var result = Parse(yaml);

        Assert.True(result.IsValid);
        Assert.Empty(result.Servers);
        Assert.Contains(result.Warnings, w => w.Contains("empty", StringComparison.Ordinal));
    }

    [Fact]
    public void Parse_WarnsWhenNoServerIsEnabled()
    {
        var result = Parse("""
            version: 1
            servers:
              off: { command: npx, disabled: true }
            """);

        Assert.True(result.IsValid);
        Assert.Equal(["off"], result.Disabled);
        Assert.Contains(result.Warnings, w => w.Contains("no enabled servers", StringComparison.Ordinal));
    }

    [Fact]
    public void Parse_RefusesADocumentThatIsNotAMapping() =>
        Assert.Contains("must be a mapping", SingleError("- a\n- b\n"), StringComparison.Ordinal);

    [Fact]
    public void Parse_ReportsYamlSyntaxErrorsWithAPosition() =>
        Assert.Contains("YAML syntax error at line", SingleError("servers: [unclosed\n"), StringComparison.Ordinal);

    [Fact]
    public void Parse_ReportsEveryErrorAtOnce()
    {
        // Five unrelated mistakes, one run: fixing a config one restart at a
        // time is the experience this rules out.
        var result = Parse("""
            version: 1
            colour: blue
            servers:
              a: { command: npx, comand: typo }
              b: { type: ws, url: wss://x.example }
              c_bad: { command: npx }
              d: { command: npx, args: ["${UNSET_ONE}"] }
            """);

        Assert.Equal(5, result.Errors.Count);
        Assert.Contains(result.Errors, e => e.Contains("Unknown key 'colour' at the top level", StringComparison.Ordinal));
        Assert.Contains(result.Errors, e => e.Contains("Server 'a': unknown key 'comand'", StringComparison.Ordinal));
        Assert.Contains(result.Errors, e => e.Contains("Server 'b': uses 'type: ws'", StringComparison.Ordinal));
        Assert.Contains(result.Errors, e => e.Contains("Server 'c_bad': the name is invalid", StringComparison.Ordinal));
        Assert.Contains(result.Errors, e => e.Contains("Server 'd': 'args[0]' references '${UNSET_ONE}'", StringComparison.Ordinal));
    }

    [Fact]
    public void Parse_WarnsAndIgnoresEveryClientOnlyKey()
    {
        var keys = string.Join(", ", ServersLoader.ClientOnlyKeys.Select(k => $"{k}: 1"));

        var server = Single($$"""
            version: 1
            servers:
              a: { command: npx, args: [pkg@1.0.0], {{keys}} }
            """);

        Assert.Equal("a", server.Name);
    }

    [Fact]
    public void Parse_PointsAClientsOAuthKey_AtTheProxysOwnLogin()
    {
        // A pasted Claude Code entry with 'oauth' is told how to have the proxy
        // log in, instead of only that OAuth is the client's business.
        var result = Parse("""
            version: 1
            servers:
              a: { type: http, url: https://mcp.example.com/mcp, oauth: { clientId: x } }
            """);

        Assert.Contains(result.Warnings, w =>
            w.Contains("'oauth'", StringComparison.Ordinal) &&
            w.Contains("x-guardrails: { oauth: {} }", StringComparison.Ordinal) &&
            w.Contains("auth login", StringComparison.Ordinal));
        Assert.DoesNotContain(
            Parse("version: 1\nservers:\n  a: { command: npx, args: [pkg@1.0.0], timeout: 5 }\n").Warnings,
            w => w.Contains("auth login", StringComparison.Ordinal));
    }

    [Fact]
    public void Parse_AcceptsAnEmptyProxyNamespace() =>
        Assert.Equal("a", Single("""
            version: 1
            servers:
              a: { command: npx, args: [pkg@1.0.0], x-guardrails: {} }
            """).Name);

    [Theory]
    [InlineData("{ future: true }")]
    [InlineData("{ oauth: { scope: [read] } }")]
    public void Parse_RefusesUnknownKeysInTheProxyNamespace(string block)
    {
        // It holds security options; a misspelt one must not be skipped quietly.
        var error = SingleError($$"""
            version: 1
            servers:
              a: { type: http, url: "https://mcp.example.com/mcp", x-guardrails: {{block}} }
            """);

        Assert.Contains("is not valid", error, StringComparison.Ordinal);
    }

    // ----------------------------------------------------------------- oauth

    [Fact]
    public void Parse_ReadsTheOAuthBlock()
    {
        var server = Single("""
            version: 1
            servers:
              linear:
                type: http
                url: https://mcp.linear.app/mcp
                x-guardrails:
                  oauth: { scopes: [read, write], client_id: guardrails, redirect_port: 8765 }
            """);

        Assert.Equal(["read", "write"], server.OAuth!.Scopes);
        Assert.Equal("guardrails", server.OAuth.ClientId);
        Assert.Equal(8765, server.OAuth.RedirectPort);
    }

    [Fact]
    public void Parse_AnEmptyOAuthBlock_MeansDynamicRegistrationAndTheServersScopes()
    {
        var server = Single("""
            version: 1
            servers:
              linear: { type: http, url: "https://mcp.linear.app/mcp", x-guardrails: { oauth: {} } }
            """);

        Assert.Empty(server.OAuth!.Scopes);
        Assert.Null(server.OAuth.ClientId);
        Assert.Null(server.OAuth.RedirectPort);
    }

    [Fact]
    public void Parse_NoOAuthBlock_MeansNoOAuth()
    {
        Assert.Null(Single("""
            version: 1
            servers:
              docs: { type: http, url: "https://mcp.example.com/mcp" }
            """).OAuth);
    }

    [Fact]
    public void Parse_RefusesOAuthOnAStdioServer()
    {
        Assert.Contains(
            "sets 'x-guardrails.oauth', which only applies to remote servers",
            SingleError("""
                version: 1
                servers:
                  a: { command: npx, args: [pkg@1.0.0], x-guardrails: { oauth: {} } }
                """),
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("headers: { Authorization: \"Bearer x\" }, x-guardrails: { oauth: {} }", "both an 'Authorization' header")]
    [InlineData("headers: { authorization: \"Bearer x\" }, x-guardrails: { oauth: {} }", "both an 'Authorization' header")]
    [InlineData("x-guardrails: { oauth: { scopes: [\"read write\"] } }", "not a single scope name")]
    [InlineData("x-guardrails: { oauth: { scopes: [\"\"] } }", "not a single scope name")]
    [InlineData("x-guardrails: { oauth: { client_id: \" \" } }", "empty 'x-guardrails.oauth.client_id'")]
    [InlineData("x-guardrails: { oauth: { redirect_port: 0 } }", "redirect_port' of 0")]
    [InlineData("x-guardrails: { oauth: { redirect_port: 70000 } }", "redirect_port' of 70000")]
    public void Parse_RefusesABadOAuthBlock(string fields, string expected)
    {
        var error = SingleError($$"""
            version: 1
            servers:
              a: { type: http, url: "https://mcp.example.com/mcp", {{fields}} }
            """);

        Assert.Contains(expected, error, StringComparison.Ordinal);
    }

    // ----------------------------------------------------------------- version

    [Fact]
    public void Parse_WarnsWhenVersionIsMissing()
    {
        var result = Parse("servers: {}\n");

        Assert.True(result.IsValid);
        Assert.Contains(result.Warnings, w => w.Contains("no 'version'", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("version: 2")]
    [InlineData("version: one")]
    [InlineData("version: [1]")]
    public void Parse_RefusesAnUnsupportedVersion(string line) =>
        Assert.Contains("'version' must be 1", SingleError($"{line}\nservers: {{}}\n"), StringComparison.Ordinal);

    // ---------------------------------------------------------------- sections

    [Theory]
    [InlineData("defaults: [1]", "'defaults' must be a mapping")]
    [InlineData("defaults: { colour: blue }", "Unknown key 'colour' in 'defaults'")]
    [InlineData("defaults: { env_passthrough: 5 }", "'defaults' is not valid")]
    [InlineData("servers: [a]", "'servers' must be a mapping")]
    [InlineData("mcpServers: 5", "'mcpServers' must be a mapping")]
    public void Parse_RefusesMalformedSections(string section, string expected) =>
        Assert.Contains(expected, SingleError($"version: 1\n{section}\n"), StringComparison.Ordinal);

    [Fact]
    public void Parse_RefusesAServerThatIsNotAMapping() =>
        Assert.Contains("Server 'a': must be a mapping", SingleError("version: 1\nservers:\n  a: npx\n"), StringComparison.Ordinal);

    [Fact]
    public void Parse_ReportsAFieldOfTheWrongType() =>
        Assert.Contains(
            "Server 'a': is not valid",
            SingleError("version: 1\nservers:\n  a: { command: npx, args: just-a-string }\n"),
            StringComparison.Ordinal);

    // --------------------------------------------------------------- transport

    [Theory]
    [InlineData("{ url: 'https://x.example/mcp' }", "has a 'url' but no 'type'")]
    [InlineData("{ args: [x] }", "needs a 'command'")]
    [InlineData("{ type: ws, url: 'wss://x.example' }", "does not support")]
    [InlineData("{ type: grpc, url: 'https://x.example' }", "unknown 'type' 'grpc'")]
    [InlineData("{ type: stdio, command: '' }", "needs a 'command'")]
    [InlineData("{ type: http }", "needs a 'url'")]
    public void Parse_RefusesAnUnusableTransport(string entry, string expected) =>
        Assert.Contains(expected, SingleError($"version: 1\nservers:\n  a: {entry}\n"), StringComparison.Ordinal);

    [Theory]
    [InlineData("stdio", UpstreamTransport.Stdio)]
    [InlineData("http", UpstreamTransport.Http)]
    [InlineData("streamable-http", UpstreamTransport.Http)]
    [InlineData("sse", UpstreamTransport.Sse)]
    public void Parse_ReadsEveryTransportName(string type, UpstreamTransport expected)
    {
        var entry = expected is UpstreamTransport.Stdio
            ? $"{{ type: {type}, command: npx, args: [pkg@1.0.0] }}"
            : $"{{ type: {type}, url: 'https://x.example/mcp' }}";

        Assert.Equal(expected, Single($"version: 1\nservers:\n  a: {entry}\n").Transport);
    }

    [Theory]
    [InlineData("url: 'https://x.example'", "'url'")]
    [InlineData("headers: { A: b }", "'headers'")]
    public void Parse_RefusesRemoteFieldsOnAStdioServer(string field, string name)
    {
        var error = SingleError($"version: 1\nservers:\n  a: {{ type: stdio, command: npx, {field} }}\n");

        Assert.Contains($"is a stdio server but sets {name}, which only applies to remote servers", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("command: npx", "'command'")]
    [InlineData("args: [x]", "'args'")]
    [InlineData("env: { A: b }", "'env'")]
    [InlineData("env_file: .env", "'env_file'")]
    [InlineData("envFile: .env", "'env_file'")]
    [InlineData("cwd: /tmp", "'cwd'")]
    [InlineData("shutdown_timeout: 5s", "'shutdown_timeout'")]
    [InlineData("env_passthrough: [A]", "'env_passthrough'")]
    [InlineData("env_isolation: true", "'env_isolation'")]
    public void Parse_RefusesStdioFieldsOnARemoteServer(string field, string name)
    {
        var error = SingleError($"version: 1\nservers:\n  a: {{ type: http, url: 'https://x.example/mcp', {field} }}\n");

        Assert.Contains($"is a remote server but sets {name}, which only applies to stdio servers", error, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- commands

    [Fact]
    public void Parse_RefusesACommandNotOnPath() =>
        Assert.Contains(
            "'command' 'nosuchtool' was not found on PATH",
            SingleError("version: 1\nservers:\n  a: { command: nosuchtool }\n"),
            StringComparison.Ordinal);

    [Fact]
    public void Parse_RefusesACommandWhoseVariableIsUnset() =>
        Assert.Contains(
            "'command' references '${SERVER_BIN}'",
            SingleError("version: 1\nservers:\n  a: { command: '${SERVER_BIN}' }\n"),
            StringComparison.Ordinal);

    [Fact]
    public void Parse_RefusesARelativeCommandPath() =>
        Assert.Contains(
            "is a relative path",
            SingleError("version: 1\nservers:\n  a: { command: ./bin/server }\n"),
            StringComparison.Ordinal);

    [Fact]
    public void Parse_AcceptsAnAbsoluteCommandThatExists()
    {
        var host = new FakeHost();
        var path = FakeHost.At("opt", "server");
        host.Files.Add(path);

        Assert.Equal(path, Single($"version: 1\nservers:\n  a: {{ command: '{path}' }}\n", host).Command);
    }

    [Fact]
    public void Parse_RefusesAnAbsoluteCommandThatDoesNotExist() =>
        Assert.Contains(
            "does not exist",
            SingleError($"version: 1\nservers:\n  a: {{ command: '{FakeHost.At("opt", "missing")}' }}\n"),
            StringComparison.Ordinal);

    [Fact]
    public void CheckCommand_SearchesPathWithWindowsExtensions()
    {
        var first = FakeHost.At("first");
        var second = FakeHost.At("second");
        var host = new FakeHost { IsWindows = true };
        host.Variables["PATH"] = $"{first};;{second}";
        host.Files.Add(Path.Combine(second, "tool.CMD"));

        Assert.Null(CommandLocator.Check("tool", host.Build()));

        host.Variables["PATHEXT"] = ".EXE";
        Assert.Equal("was not found on PATH", CommandLocator.Check("tool", host.Build()));
    }

    [Fact]
    public void CheckCommand_ToleratesAnUnsetPath()
    {
        var host = new FakeHost();
        host.Variables.Remove("PATH");

        Assert.Equal("was not found on PATH", CommandLocator.Check("npx", host.Build()));
    }

    [Fact]
    public void Parse_WarnsAboutAnUnpinnedPackage()
    {
        var result = Parse("version: 1\nservers:\n  a: { command: npx, args: [-y, some-server] }\n");

        Assert.True(result.IsValid);
        Assert.Contains(result.Warnings, w => w.Contains("'some-server'", StringComparison.Ordinal));
    }

    [Fact]
    public void Parse_DoesNotWarnAboutAPinnedPackage() =>
        Assert.DoesNotContain(
            Parse("version: 1\nservers:\n  a: { command: npx, args: [-y, some-server@1.2.3], env_isolation: false }\n").Warnings,
            w => w.Contains("pinned", StringComparison.Ordinal));

    [Fact]
    public void Parse_MasksASecretWrittenIntoTheCommandLine()
    {
        var server = Single(
            $"version: 1\nservers:\n  a: {{ command: npx, args: [pkg@1.0.0, --token, '{SecretSamples.GitHubToken}'] }}\n");

        Assert.Equal(SecretSamples.GitHubToken, server.Arguments[2]);
        Assert.DoesNotContain(SecretSamples.GitHubToken, server.DisplayTemplate, StringComparison.Ordinal);
    }

    // --------------------------------------------------- working dir and env

    [Fact]
    public void Parse_ResolvesARelativeWorkingDirectoryAgainstTheFile()
    {
        var host = new FakeHost();
        host.Directories.Add(Path.Combine(_base, "work"));

        Assert.Equal(
            Path.Combine(_base, "work"),
            Single("version: 1\nservers:\n  a: { command: npx, args: [p@1.0.0], cwd: work }\n", host).WorkingDirectory);
    }

    [Fact]
    public void Parse_RefusesAWorkingDirectoryThatDoesNotExist() =>
        Assert.Contains(
            "'cwd' 'nowhere' is not an existing directory",
            SingleError("version: 1\nservers:\n  a: { command: npx, cwd: nowhere }\n"),
            StringComparison.Ordinal);

    [Fact]
    public void Parse_SkipsAWorkingDirectoryWhoseVariableIsUnset() =>
        Assert.Contains(
            "'cwd' references '${NOPE}'",
            SingleError("version: 1\nservers:\n  a: { command: npx, cwd: '${NOPE}' }\n"),
            StringComparison.Ordinal);

    [Fact]
    public void Parse_ReadsAnEnvFileAndLetsEnvWin()
    {
        var host = new FakeHost();
        host.Contents[Path.Combine(_base, ".env")] = """
            # a comment

            export FROM_FILE="quoted value"
            SHARED=file
            SINGLE='x'
            """;

        var server = Single("""
            version: 1
            servers:
              a:
                command: npx
                args: [p@1.0.0]
                envFile: .env
                env: { SHARED: env, PORT: 8080, DEBUG: true, QUIET: false, UNSET_ME: null }
                env_isolation: false
            """, host);

        var env = server.EnvironmentVariables!;
        Assert.Equal("quoted value", env["FROM_FILE"]);
        Assert.Equal("env", env["SHARED"]);
        Assert.Equal("x", env["SINGLE"]);
        Assert.Equal("8080", env["PORT"]);
        Assert.Equal("true", env["DEBUG"]);
        Assert.Equal("false", env["QUIET"]);
        Assert.Null(env["UNSET_ME"]);
    }

    [Fact]
    public void Parse_RefusesBothEnvFileSpellings() =>
        Assert.Contains(
            "both 'env_file' and 'envFile'",
            Parse("version: 1\nservers:\n  a: { command: npx, env_file: a, envFile: b }\n").Errors[0],
            StringComparison.Ordinal);

    [Fact]
    public void Parse_ReportsAnUnreadableEnvFile()
    {
        var host = new FakeHost();
        host.Unreadable[Path.Combine(_base, "locked.env")] = new UnauthorizedAccessException("denied");

        Assert.Contains(
            "'env_file' 'locked.env' could not be read: denied",
            SingleError("version: 1\nservers:\n  a: { command: npx, env_file: locked.env }\n", host),
            StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_ReportsAMissingEnvFile() =>
        Assert.Contains(
            "could not be read",
            SingleError("version: 1\nservers:\n  a: { command: npx, env_file: missing.env }\n"),
            StringComparison.Ordinal);

    [Fact]
    public void Parse_ReportsAMalformedEnvFileWithoutEchoingIt()
    {
        var host = new FakeHost();
        host.Contents[Path.Combine(_base, ".env")] = "GOOD=1\nthis is secret-ish text\n";

        var error = SingleError("version: 1\nservers:\n  a: { command: npx, env_file: .env }\n", host);

        Assert.Contains("line 2 is not a KEY=VALUE pair", error, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-ish", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_SkipsAnEnvFileWhoseVariableIsUnset() =>
        Assert.Contains(
            "'env_file' references '${NOPE}'",
            SingleError("version: 1\nservers:\n  a: { command: npx, env_file: '${NOPE}' }\n"),
            StringComparison.Ordinal);

    [Fact]
    public void Parse_RefusesAStructuredEnvValue() =>
        Assert.Contains(
            "'env.A' must be a string, number, boolean or null",
            SingleError("version: 1\nservers:\n  a: { command: npx, env: { A: [1] } }\n"),
            StringComparison.Ordinal);

    [Theory]
    [InlineData("a=b", "a", "b")]
    [InlineData("  KEY = spaced  ", "KEY", "spaced")]
    [InlineData("K=\"unbalanced'", "K", "\"unbalanced'")]
    [InlineData("K=\"\"", "K", "")]
    [InlineData("K=\"", "K", "\"")]
    [InlineData("K=a=b", "K", "a=b")]
    public void ParseEnvFile_ReadsDotenvLines(string line, string key, string value)
    {
        var variables = EnvFile.Parse(line + "\r\n", out var error);

        Assert.Null(error);
        Assert.Equal(value, variables![key]);
    }

    [Theory]
    [InlineData("=value")]
    [InlineData("no-equals")]
    [InlineData("1BAD=x")]
    public void ParseEnvFile_RefusesWhatIsNotAPair(string line)
    {
        Assert.Null(EnvFile.Parse(line, out var error));
        Assert.Equal("line 1 is not a KEY=VALUE pair", error);
    }

    // ---------------------------------------------------------------- durations

    [Theory]
    [InlineData("5s", 5_000)]
    [InlineData("500ms", 500)]
    [InlineData("2m", 120_000)]
    [InlineData("1.5s", 1_500)]
    [InlineData("7", 7_000)]
    public void Parse_ReadsShutdownTimeouts(string value, int milliseconds) =>
        Assert.Equal(
            TimeSpan.FromMilliseconds(milliseconds),
            Single($"version: 1\nservers:\n  a: {{ command: npx, args: [p@1.0.0], shutdown_timeout: '{value}' }}\n").ShutdownTimeout);

    [Fact]
    public void Parse_ReadsANumericShutdownTimeoutFromDefaults() =>
        Assert.Equal(
            TimeSpan.FromSeconds(3),
            Single("version: 1\ndefaults: { shutdown_timeout: 3 }\nservers:\n  a: { command: npx, args: [p@1.0.0] }\n").ShutdownTimeout);

    [Theory]
    [InlineData("'abc'")]
    [InlineData("'-1s'")]
    [InlineData("-1")]
    [InlineData("true")]
    public void Parse_RefusesAMalformedShutdownTimeout(string value) =>
        Assert.Contains(
            "'shutdown_timeout' must be a duration",
            SingleError($"version: 1\nservers:\n  a: {{ command: npx, shutdown_timeout: {value} }}\n"),
            StringComparison.Ordinal);

    [Fact]
    public void TryParseDuration_RefusesNonScalars()
    {
        using var document = JsonDocument.Parse("[1]");

        Assert.False(Durations.TryParse(document.RootElement, out _));
    }

    // ----------------------------------------------------- disabled and optional

    [Fact]
    public void Parse_SkipsADisabledServerEntirely()
    {
        // Its variable is unset, which would be an error on an enabled server.
        var result = Parse("""
            version: 1
            servers:
              on: { command: npx, args: [p@1.0.0] }
              off: { command: npx, args: ["${NOT_SET}"], disabled: true }
            """);

        Assert.True(result.IsValid);
        Assert.Equal(["on"], result.Servers.Select(s => s.Name));
        Assert.Equal(["off"], result.Disabled);
    }

    [Fact]
    public void Parse_ReadsOptional()
    {
        Assert.True(Single("version: 1\nservers:\n  a: { type: http, url: 'https://x.example', optional: true }\n").Optional);
        Assert.True(Single("version: 1\nservers:\n  a: { command: npx, args: [p@1.0.0], optional: true }\n").Optional);
        Assert.False(Single("version: 1\nservers:\n  a: { command: npx, args: [p@1.0.0] }\n").Optional);
    }

    // ------------------------------------------------------------- remote URLs

    [Theory]
    [InlineData("ftp://x.example/mcp", "Use https")]
    [InlineData("http://x.example/mcp", "plain http")]
    [InlineData("https://user:pw@x.example/mcp", "contains credentials")]
    [InlineData("not a url", "not an absolute URL")]
    public void Parse_RefusesAnUnsafeUrl(string url, string expected)
    {
        var error = SingleError($"version: 1\nservers:\n  a: {{ type: http, url: '{url}' }}\n");

        Assert.Contains("'servers.a.url'", error, StringComparison.Ordinal);
        Assert.Contains(expected, error, StringComparison.Ordinal);
        Assert.DoesNotContain("pw", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_AcceptsPlainHttpToLoopback() =>
        Assert.Equal(
            new Uri("http://localhost:3000/mcp"),
            Single("version: 1\nservers:\n  a: { type: http, url: 'http://localhost:3000/mcp' }\n").Url);

    [Fact]
    public void Parse_RefusesAUrlWhoseVariableIsUnset() =>
        Assert.Contains(
            "'url' references '${HOST}'",
            SingleError("version: 1\nservers:\n  a: { type: http, url: 'https://${HOST}/mcp' }\n"),
            StringComparison.Ordinal);

    [Fact]
    public void Parse_RefusesAHeaderWhoseVariableIsUnset() =>
        Assert.Contains(
            "'headers.Authorization' references '${TOKEN}'",
            SingleError("version: 1\nservers:\n  a: { type: http, url: 'https://x.example', headers: { Authorization: 'Bearer ${TOKEN}' } }\n"),
            StringComparison.Ordinal);

    // ------------------------------------------------------- environment isolation

    private static FakeHost IsolationHost()
    {
        var host = new FakeHost();
        host.Variables["ANTHROPIC_API_KEY"] = "sk-proxy-secret";
        host.Variables["NODE_OPTIONS"] = "--max-old-space-size=512";
        host.Variables["NODE_ENV"] = "production";
        return host;
    }

    [Fact]
    public void Isolation_GivesTheChildOnlyTheAllowlistPassthroughAndItsOwnEnv()
    {
        var server = Single("""
            version: 1
            defaults:
              env_isolation: true
              env_passthrough: [NODE_*]
            servers:
              a:
                command: npx
                args: [p@1.0.0]
                env: { OWN: mine, PATH: overridden }
            """, IsolationHost());

        var env = server.EnvironmentVariables!;
        Assert.False(server.InheritEnvironment);
        Assert.False(env.ContainsKey("ANTHROPIC_API_KEY"));
        Assert.Equal("production", env["NODE_ENV"]);
        Assert.Equal("--max-old-space-size=512", env["NODE_OPTIONS"]);
        Assert.Equal(FakeHost.Home, env["HOME"]);
        Assert.Equal("mine", env["OWN"]);
        Assert.Equal("overridden", env["PATH"]);
    }

    [Fact]
    public void Isolation_CanBeSwitchedOnPerServer()
    {
        var server = Single("""
            version: 1
            servers:
              a: { command: npx, args: [p@1.0.0], env_isolation: true, env_passthrough: [NODE_ENV] }
            """, IsolationHost());

        Assert.False(server.InheritEnvironment);
        Assert.Equal("production", server.EnvironmentVariables!["NODE_ENV"]);
        Assert.False(server.EnvironmentVariables.ContainsKey("NODE_OPTIONS"));
    }

    [Fact]
    public void Isolation_IsUndoneByAStarPassthroughWithAWarning()
    {
        var result = Parse("""
            version: 1
            servers:
              a: { command: npx, args: [p@1.0.0], env_isolation: true, env_passthrough: ["*"] }
            """, IsolationHost());

        Assert.True(Assert.Single(result.Servers).InheritEnvironment);
        Assert.Contains(result.Warnings, w => w.Contains("contains '*'", StringComparison.Ordinal));
    }

    [Fact]
    public void Isolation_WhenUnsetInheritsAndWarnsWithNamesNeverValues()
    {
        var result = Parse("version: 1\nservers:\n  a: { command: npx, args: [p@1.0.0] }\n", IsolationHost());

        var server = Assert.Single(result.Servers);
        Assert.True(server.InheritEnvironment);

        var warning = Assert.Single(result.Warnings);
        Assert.Contains("Server 'a': inherits the proxy's whole environment", warning, StringComparison.Ordinal);
        Assert.Contains("ANTHROPIC_API_KEY, NODE_ENV, NODE_OPTIONS", warning, StringComparison.Ordinal);
        Assert.DoesNotContain("sk-proxy-secret", warning, StringComparison.Ordinal);
        Assert.DoesNotContain("PATH", warning, StringComparison.Ordinal);
    }

    [Fact]
    public void Isolation_ExplicitlyOffInheritsWithoutAWarning()
    {
        var result = Parse("version: 1\nservers:\n  a: { command: npx, args: [p@1.0.0], env_isolation: false }\n", IsolationHost());

        Assert.True(Assert.Single(result.Servers).InheritEnvironment);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public void Isolation_WhenUnsetDoesNotWarnIfNothingWouldBeWithheld() =>
        Assert.Empty(Parse("version: 1\nservers:\n  a: { command: npx, args: [p@1.0.0] }\n").Warnings);

    // ----------------------------------------------------------- results and files

    [Fact]
    public void EnsureValid_ReturnsTheServersOrThrowsWithEveryError()
    {
        var valid = Parse("version: 1\nservers:\n  a: { command: npx, args: [p@1.0.0] }\n");
        Assert.Same(valid.Servers, valid.EnsureValid());

        var invalid = Parse("version: 1\nservers:\n  a: { command: nope }\n  b: { command: nope }\n");
        var exception = Assert.Throws<ServersException>(invalid.EnsureValid);
        Assert.Equal(2, exception.Errors.Count);
        Assert.Contains("Server 'b'", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LoadFile_ReadsAFileAndResolvesPathsAgainstItsDirectory()
    {
        var host = new FakeHost();
        var path = Path.Combine(_base, "servers.yaml");
        host.Contents[path] = "version: 1\nservers:\n  a: { command: npx, args: [p@1.0.0], cwd: work }\n";
        host.Directories.Add(Path.Combine(_base, "work"));
        host.Modes[path] = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead;

        var result = ServersLoader.LoadFile(path, host.Build());

        Assert.True(result.IsValid, string.Join("\n", result.Errors));
        Assert.Empty(result.Warnings);
        Assert.Equal(Path.Combine(_base, "work"), Assert.Single(result.Servers).WorkingDirectory);
    }

    [Fact]
    public void LoadFile_SkipsThePermissionCheckWhereThereAreNoModes()
    {
        var host = new FakeHost();
        var path = Path.Combine(_base, "servers.yaml");
        host.Contents[path] = "version: 1\nservers: {}\n";

        Assert.DoesNotContain(
            ServersLoader.LoadFile(path, host.Build()).Warnings,
            w => w.Contains("writable", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(UnixFileMode.GroupWrite)]
    [InlineData(UnixFileMode.OtherWrite)]
    public void LoadFile_WarnsWhenOthersCanWriteTheFile(UnixFileMode mode)
    {
        var host = new FakeHost();
        var path = Path.Combine(_base, "servers.yaml");
        host.Contents[path] = "version: 1\nservers: {}\n";
        host.Modes[path] = UnixFileMode.UserRead | mode;

        var result = ServersLoader.LoadFile(path, host.Build());

        Assert.Contains(result.Warnings, w => w.Contains("writable by other users", StringComparison.Ordinal));
    }

    [Fact]
    public void LoadFile_RefusesADirectory()
    {
        var host = new FakeHost();
        host.Directories.Add(_base);

        Assert.Contains("is a directory", Assert.Single(ServersLoader.LoadFile(_base, host.Build()).Errors), StringComparison.Ordinal);
    }

    [Fact]
    public void LoadFile_RefusesAMissingFile() =>
        Assert.Contains(
            "does not exist",
            Assert.Single(ServersLoader.LoadFile(Path.Combine(_base, "nope.yaml"), new FakeHost().Build()).Errors),
            StringComparison.Ordinal);

    [Fact]
    public void LoadFile_ReportsAnUnreadableFile()
    {
        var host = new FakeHost();
        var path = Path.Combine(_base, "servers.yaml");
        host.Files.Add(path);
        host.Unreadable[path] = new IOException("locked");

        Assert.Contains(
            "Could not read servers file",
            Assert.Single(ServersLoader.LoadFile(path, host.Build()).Errors),
            StringComparison.Ordinal);
    }

    [Fact]
    public void Loader_RejectsNullArguments()
    {
        var host = new FakeHost().Build();

        Assert.Throws<ArgumentNullException>(() => ServersLoader.Parse(null!, _base, host));
        Assert.Throws<ArgumentNullException>(() => ServersLoader.Parse("", null!, host));
        Assert.Throws<ArgumentNullException>(() => ServersLoader.Parse("", _base, null!));
        Assert.Throws<ArgumentNullException>(() => ServersLoader.LoadFile(null!, host));
        Assert.Throws<ArgumentNullException>(() => ServersLoader.LoadFile("x", null!));
    }

    [Theory]
    [InlineData("npx", new[] { "-y", "pkg" }, "npx -y pkg")]
    [InlineData("npx", new[] { "a b", "", "say \"hi\"" }, "npx \"a b\" \"\" \"say \\\"hi\\\"\"")]
    public void DisplayCommandLine_QuotesWhatNeedsIt(string command, string[] arguments, string expected) =>
        Assert.Equal(expected, ServersLoader.DisplayCommandLine(command, arguments));
}
