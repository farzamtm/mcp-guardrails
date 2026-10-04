using System.Net;
using McpGuardrails.Core.Access;
using McpGuardrails.Core.Budget;
using McpGuardrails.Core.Hosting;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Hosting;

public sealed class ServeOptionsTests
{
    private const string _token = "0123456789abcdef0123";

    private static ServeOptions Parse(string commandLine, string? token = null) =>
        ServeOptions.Parse(
            commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            token);

    private static string Rejected(string commandLine, string? token = null) =>
        Assert.Throws<ServeOptionsException>(() => Parse(commandLine, token)).Message;

    // ----------------------------------------------------------------- stdio

    [Theory]
    [InlineData("")]
    [InlineData("--explain list-upstream")]
    [InlineData("--transport stdio")]
    public void WithoutAnHttpTransport_ItIsStdio(string commandLine)
    {
        Assert.Same(ServeOptions.Default, Parse(commandLine));
        Assert.Equal(Transport.Stdio, ServeOptions.Default.Transport);
    }

    [Fact]
    public void Stdio_IgnoresATokenLeftInTheEnvironment()
    {
        // The variable may be exported for the whole shell; stdio has no network.
        var options = Parse("", token: "short");

        Assert.Null(options.BearerToken);
        Assert.False(options.RequiresToken);
    }

    [Theory]
    [InlineData("--port 8080")]
    [InlineData("--bind 127.0.0.1")]
    [InlineData("--transport stdio --port 8080")]
    public void NetworkFlags_WithStdio_AreAnError(string commandLine)
    {
        Assert.Contains("only apply to '--transport http'", Rejected(commandLine), StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ http

    [Fact]
    public void Http_DefaultsToLoopbackOnTheDefaultPort_WithoutAToken()
    {
        var options = Parse("--transport http");

        Assert.Equal(Transport.Http, options.Transport);
        Assert.Equal(IPAddress.Loopback, options.BindAddress);
        Assert.Equal(ServeOptions.DefaultPort, options.Port);
        Assert.False(options.RequiresToken);
    }

    [Theory]
    [InlineData("0", 0)]
    [InlineData("8080", 8080)]
    [InlineData("65535", 65535)]
    public void Http_TakesAnyValidPort_IncludingZeroForAnEphemeralOne(string port, int expected)
    {
        Assert.Equal(expected, Parse($"--transport http --port {port}").Port);
    }

    [Theory]
    [InlineData("65536")]
    [InlineData("-1")]
    [InlineData("80a")]
    [InlineData("+80")]
    public void Http_RejectsAPortThatIsNotOne(string port)
    {
        Assert.Contains("is not a port number", Rejected($"--transport http --port {port}"), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("127.0.0.2")]
    public void Http_BindsAnyLoopbackAddress_WithoutAToken(string address)
    {
        Assert.Equal(IPAddress.Parse(address), Parse($"--transport http --bind {address}").BindAddress);
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("192.168.1.10")]
    public void Http_RefusesANonLoopbackBind_WithoutAToken(string address)
    {
        // Nothing else authenticates the caller, so this is not offered at all.
        Assert.Contains("without authentication", Rejected($"--transport http --bind {address}"), StringComparison.Ordinal);
    }

    [Fact]
    public void Http_AllowsANonLoopbackBind_WithAToken()
    {
        var options = Parse("--transport http --bind 0.0.0.0", token: _token);

        Assert.Equal(IPAddress.Any, options.BindAddress);
        Assert.True(options.RequiresToken);
        Assert.Equal(_token, options.BearerToken);
    }

    [Fact]
    public void Http_TrimsTheToken()
    {
        // A trailing newline from `$(cat token-file)` must not lock everyone out.
        Assert.Equal(_token, Parse("--transport http", token: $" {_token}\n").BearerToken);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("tooshort")]
    [InlineData("  fifteen-chars  ")]
    public void Http_RejectsATokenTooShortToBeOne(string token)
    {
        // Set-but-useless is a mistake, not "no token": failing open here would
        // serve an unauthenticated endpoint to someone who asked for auth.
        Assert.Contains("at least", Rejected("--transport http", token), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("example.com")]
    public void Http_RejectsAHostName(string bind)
    {
        Assert.Contains("is not an IP address", Rejected($"--transport http --bind {bind}"), StringComparison.Ordinal);
    }

    // --------------------------------------------------------------- syntax

    [Fact]
    public void AnUnknownTransport_IsAnError()
    {
        Assert.Contains("Unknown transport 'sse'", Rejected("--transport sse"), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--transport")]
    [InlineData("--transport http --port")]
    [InlineData("--transport http --bind --port 1")]
    public void AFlagWithoutAValue_IsAnError(string commandLine)
    {
        Assert.Contains("needs a value", Rejected(commandLine), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--transport http --transport stdio")]
    [InlineData("--transport http --port 1 --port 2")]
    [InlineData("--transport http --bind ::1 --bind 127.0.0.1")]
    public void ARepeatedFlag_IsAnError_RatherThanLastOneWins(string commandLine)
    {
        Assert.Contains("more than once", Rejected(commandLine), StringComparison.Ordinal);
    }

    [Fact]
    public void NullArguments_Throw()
    {
        Assert.Throws<ArgumentNullException>(() => ServeOptions.Parse(null!, null));
    }

    // -------------------------------------------------------------- budgets

    private static readonly BudgetLimits _limits = new() { MaxCalls = 5 };

    [Fact]
    public void Http_RefusesASessionBudget_AndSaysWhatToUseInstead()
    {
        // Stateless HTTP has no session: the cap would silently become one pool
        // shared by every client for the life of the process.
        var message = Assert.Throws<ServeOptionsException>(
            () => Parse("--transport http").EnsureEnforceable(new BudgetPolicy { Session = _limits })).Message;

        Assert.Contains("'budgets.session' cannot be enforced over '--transport http'", message, StringComparison.Ordinal);
        Assert.Contains("shared by every client", message, StringComparison.Ordinal);
        Assert.Contains("'budgets.daily'", message, StringComparison.Ordinal);
        Assert.Contains("stdio", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Http_RefusesASessionBudget_EvenAlongsideADailyOne()
    {
        // The daily cap being fine does not make the session cap mean what it says.
        Assert.Throws<ServeOptionsException>(
            () => Parse("--transport http").EnsureEnforceable(
                new BudgetPolicy { Session = _limits, Daily = _limits }));
    }

    [Fact]
    public void Http_AcceptsADailyBudget_OrNone()
    {
        var http = Parse("--transport http");

        http.EnsureEnforceable(new BudgetPolicy { Daily = _limits });
        http.EnsureEnforceable(BudgetPolicy.None);
    }

    [Fact]
    public void Stdio_AcceptsASessionBudget()
    {
        // One process per client session, so "session" means exactly that.
        ServeOptions.Default.EnsureEnforceable(new BudgetPolicy { Session = _limits, Daily = _limits });
    }

    [Fact]
    public void Http_DailyOnlyPolicy_StillChargesPerRuleCosts()
    {
        // The policy an HTTP operator is now pointed at: per-rule `cost:` must
        // keep working with only a daily cap, or the advice would be a downgrade.
        var document = PolicyLoader.Parse("""
            budgets:
              daily:
                max_cost: 5
            rules:
              - name: reads-are-free
                match:
                  tool: fs__read_*
                decision: allow
                cost: 0
              - name: writes-cost
                match:
                  tool: fs__write_*
                decision: allow
                cost: 3
            """);

        Parse("--transport http").EnsureEnforceable(document.EffectiveBudgets);

        // An in-memory store standing in for SQLite: the arithmetic is the same.
        var gate = BudgetGate.For(document.EffectiveBudgets, limits => new InMemoryBudgetStore(limits));
        var evaluator = new PolicyEvaluator(document);
        Decision Call(string tool) => gate.Apply(evaluator.Evaluate(new ToolCallFacts(tool)));

        Assert.False(Call("fs__write_file").IsBlocked);
        Assert.Equal("daily.max_cost", Call("fs__write_file").RuleName);
        Assert.False(Call("fs__read_text_file").IsBlocked);
    }

    [Fact]
    public void NullBudgets_Throw()
    {
        Assert.Throws<ArgumentNullException>(() => ServeOptions.Default.EnsureEnforceable(null!));
    }

    // ----------------------------------------------------------------- oauth

    private static readonly OAuthSettings _oauth = PolicyLoader.Parse("""
        access:
          oauth:
            issuer: https://login.example.com
            audience: api://mcp-guardrails
        """).EffectiveAccess.OAuth!;

    private static ServeOptions ParseWithOAuth(string commandLine, string? token = null) =>
        ServeOptions.Parse(commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries), token, _oauth);

    [Fact]
    public void OAuth_IsCarriedOnTheOptions()
    {
        var options = ParseWithOAuth("--transport http");

        Assert.Same(_oauth, options.OAuth);
        Assert.False(options.RequiresToken);
        Assert.Equal("OAuth access tokens", options.AuthenticationName);
    }

    [Fact]
    public void OAuth_CountsAsAuthentication_ForANonLoopbackBind()
    {
        var options = ParseWithOAuth("--transport http --bind 0.0.0.0");

        Assert.Equal(IPAddress.Any, options.BindAddress);
    }

    [Fact]
    public void OAuth_AndTheStaticToken_TogetherAreRefused()
    {
        // Two policies about who may call, and whichever one the operator forgot
        // about is the one an attacker uses.
        var message = Assert.Throws<ServeOptionsException>(() => ParseWithOAuth("--transport http", _token)).Message;

        Assert.Contains("Choose one", message, StringComparison.Ordinal);
    }

    [Fact]
    public void OAuth_OverStdio_IsRefused()
    {
        var message = Assert.Throws<ServeOptionsException>(() => ParseWithOAuth("")).Message;

        Assert.Contains("only applies to '--transport http'", message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheAuthenticationName_DescribesEachMode()
    {
        Assert.Equal("bearer token", Parse("--transport http", _token).AuthenticationName);
        Assert.Equal("none (loopback only)", Parse("--transport http").AuthenticationName);
    }

    [Fact]
    public void ASessionBudgetOverHttp_SuggestsThePrincipalBudget()
    {
        var message = Assert.Throws<ServeOptionsException>(
            () => Parse("--transport http").EnsureEnforceable(new BudgetPolicy { Session = new BudgetLimits { MaxCalls = 1 } })).Message;

        Assert.Contains("'budgets.principal' with 'access.oauth'", message, StringComparison.Ordinal);
    }
}
