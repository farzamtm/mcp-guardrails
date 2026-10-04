using McpGuardrails.Core.Packs;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Tests.Packs;

public sealed class PackSelectionTests
{
    private static readonly PackCatalog _catalog = PackCatalog.FromTexts(
    [
        PolicyPackTests.PackText("alpha", header: Header("alpha-server")),
        PolicyPackTests.PackText("beta", header: Header("beta-server")),
    ]);

    private static string Header(string recognizes) =>
        "pack:\n  name: {0}\n  version: 1\n  description: d\n  recognizes: [" + recognizes + "]\n";

    private static UpstreamServerConfig Server(string name, string template) =>
        new() { Name = name, Command = "x", DisplayTemplate = template };

    private static readonly IReadOnlyList<UpstreamServerConfig> _servers =
    [
        Server("a", "npx -y alpha-server@1"),
        Server("b", "uvx beta-server"),
        Server("other", "node other.js"),
    ];

    [Theory]
    [InlineData("alpha", "alpha", null)]
    [InlineData("alpha=a", "alpha", "a")]
    [InlineData("alpha=", "alpha", "")]
    public void PackRequest_ParsesPackAndServer(string value, string pack, string? server) =>
        Assert.Equal(new PackRequest(pack, server), PackRequest.Parse(value));

    [Fact]
    public void NoRequests_SuggestsAPackForEachRecognizedServer()
    {
        var result = PackSelection.Resolve(_catalog, [], _servers);

        Assert.Empty(result.Errors);
        Assert.Equal(
            [("alpha", "a", "recognized alpha-server"), ("beta", "b", "recognized beta-server")],
            result.Assignments.Select(x => (x.Pack.Name, x.Server, x.Reason)));
        Assert.Equal(["other"], result.Unassigned);
    }

    [Fact]
    public void NoRequests_NothingRecognized_IsAnError()
    {
        var result = PackSelection.Resolve(_catalog, [], [Server("other", "node other.js")]);

        Assert.Empty(result.Assignments);
        Assert.Contains("No pack recognizes any configured server", Assert.Single(result.Errors));
        Assert.Contains("alpha, beta", result.Errors[0]);
    }

    [Fact]
    public void UnknownPack_IsAnError()
    {
        var result = PackSelection.Resolve(_catalog, [new PackRequest("gamma", null)], _servers);

        Assert.Contains("no pack called 'gamma'", Assert.Single(result.Errors));
    }

    [Fact]
    public void NamedServer_IsUsedAsGiven()
    {
        var result = PackSelection.Resolve(_catalog, [new PackRequest("beta", "other")], _servers);

        Assert.Empty(result.Warnings);
        var assignment = Assert.Single(result.Assignments);
        Assert.Equal(("beta", "other", "named on the command line"), (assignment.Pack.Name, assignment.Server, assignment.Reason));
        Assert.Equal(["a", "b"], result.Unassigned);
    }

    [Fact]
    public void NamedServerThatIsNotConfigured_IsAWarning()
    {
        var result = PackSelection.Resolve(_catalog, [new PackRequest("alpha", "later")], _servers);

        Assert.Empty(result.Errors);
        Assert.Contains("No configured server is called 'later'", Assert.Single(result.Warnings));
        Assert.Equal("later", Assert.Single(result.Assignments).Server);
    }

    [Theory]
    [InlineData("")]
    [InlineData("bad_name")]
    public void InvalidServerName_IsAnError(string server)
    {
        var result = PackSelection.Resolve(_catalog, [new PackRequest("alpha", server)], _servers);

        Assert.Contains("is not a valid server name", Assert.Single(result.Errors));
    }

    [Fact]
    public void UnnamedServer_GoesToEveryServerThePackRecognizes()
    {
        IReadOnlyList<UpstreamServerConfig> servers =
            [Server("a1", "alpha-server"), Server("a2", "docker run ghcr.io/x/alpha-server:1"), Server("b", "beta-server")];

        var result = PackSelection.Resolve(_catalog, [new PackRequest("alpha", null)], servers);

        Assert.Equal(["a1", "a2"], result.Assignments.Select(x => x.Server));
        Assert.Equal(["b"], result.Unassigned);
    }

    [Fact]
    public void UnnamedServerNotRecognized_IsAnErrorListingTheServers()
    {
        var result = PackSelection.Resolve(_catalog, [new PackRequest("alpha", null)], [Server("other", "node x")]);

        var error = Assert.Single(result.Errors);
        Assert.Contains("(other)", error);
        Assert.Contains("--pack alpha=<server>", error);
    }

    [Fact]
    public void UnnamedServerWithNoServersAtAll_SaysNone()
    {
        var result = PackSelection.Resolve(_catalog, [new PackRequest("alpha", null)], []);

        Assert.Contains("(none)", Assert.Single(result.Errors));
    }

    [Fact]
    public void TwoPacksForOneServer_IsAnError_AndAssignsNothing()
    {
        var result = PackSelection.Resolve(
            _catalog,
            [new PackRequest("alpha", null), new PackRequest("beta", "a")],
            _servers);

        Assert.Contains("Server 'a' would get more than one pack (alpha, beta)", Assert.Single(result.Errors));
        Assert.Empty(result.Assignments);
    }
}
