using McpGuardrails.Core.Pins;
using McpGuardrails.Core.Tests.Upstream;
using McpGuardrails.Core.Upstream;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Server;
using static McpGuardrails.Core.Tests.Pins.PinTestData;

namespace McpGuardrails.Core.Tests.Pins;

/// <summary>
/// Tests for comparing what servers serve with what was pinned: every row of
/// "seen before or not, tool changed, added, removed, identity changed".
/// </summary>
public sealed class PinCheckTests
{
    [Fact]
    public void AServerNeverSeen_IsTrustedOnFirstUse()
    {
        var result = PinCheck.Run(null, [Subject("fs", Identity, Tool("read"), Tool("write"))], PinnedAt);

        var report = Assert.Single(result.Reports);
        Assert.True(report.FirstSeen);
        Assert.True(report.HasDifferences);
        Assert.Null(report.ChangeOf("read"));
        Assert.Equal(["fs"], result.NewlyPinned);
        Assert.True(result.DocumentChanged);

        var pinned = result.Document.EffectiveServers["fs"];
        Assert.Equal(Identity, pinned.Identity);
        Assert.Equal("fs-command", pinned.IdentityHint);
        Assert.Equal(PinnedAt, pinned.PinnedAt);
        Assert.Equal(ToolDefinition.Hash(Tool("read")), pinned.EffectiveTools["read"].Hash);
        Assert.Equal(ToolDefinition.Canonical(Tool("read")), PinsFile.Decompress(pinned.EffectiveTools["read"].Definition!));
    }

    [Fact]
    public void AServerThatMatches_HasNoDifferences_AndIsNotRewritten()
    {
        var existing = PinsDocument.Empty.With("fs", Pinned(Identity, Tool("read")));

        var result = PinCheck.Run(existing, [Subject("fs", Identity, Tool("read"))], PinnedAt.AddDays(1));

        var report = Assert.Single(result.Reports);
        Assert.False(report.HasDifferences);
        Assert.Null(report.ChangeOf("read"));
        Assert.False(result.DocumentChanged);
        Assert.Same(existing, result.Document);
        Assert.Equal(PinnedAt, report.PinnedAt);
        Assert.Equal("fs-command", report.PinnedHint);
    }

    [Fact]
    public void ChangedAddedAndRemovedTools_AreEachReported()
    {
        var existing = PinsDocument.Empty.With("fs", Pinned(Identity, Tool("read"), Tool("write"), Tool("gone-b"), Tool("gone-a")));

        var result = PinCheck.Run(
            existing,
            [Subject("fs", Identity, Tool("read", "Now also uploads files."), Tool("write"), Tool("delete"))],
            PinnedAt);

        var report = Assert.Single(result.Reports);
        Assert.Equal(["read"], report.Changed);
        Assert.Equal(["delete"], report.Added);
        Assert.Equal(["gone-a", "gone-b"], report.Removed);
        Assert.Equal(PinChange.Changed, report.ChangeOf("read"));
        Assert.Equal(PinChange.Added, report.ChangeOf("delete"));
        Assert.Null(report.ChangeOf("write"));
        Assert.Null(report.ChangeOf("gone-a"));
        Assert.True(report.HasDifferences);

        // Never re-pinned automatically: the file still holds the old definitions.
        Assert.False(result.DocumentChanged);
        Assert.Same(existing, result.Document);
    }

    [Fact]
    public void ARemovedToolAlone_IsADifference()
    {
        var existing = PinsDocument.Empty.With("fs", Pinned(Identity, Tool("read"), Tool("gone")));

        var report = Assert.Single(PinCheck.Run(existing, [Subject("fs", Identity, Tool("read"))], PinnedAt).Reports);

        Assert.True(report.HasDifferences);
        Assert.Equal(["gone"], report.Removed);
    }

    [Fact]
    public void AnAddedToolAlone_IsADifference()
    {
        var existing = PinsDocument.Empty.With("fs", Pinned(Identity, Tool("read")));

        var report = Assert.Single(PinCheck.Run(existing, [Subject("fs", Identity, Tool("read"), Tool("new"))], PinnedAt).Reports);

        Assert.True(report.HasDifferences);
    }

    [Fact]
    public void AChangedIdentity_PutsEveryToolInQuestion_EvenIdenticalOnes()
    {
        var existing = PinsDocument.Empty.With("fs", Pinned(Identity, Tool("read")));

        var report = Assert.Single(
            PinCheck.Run(existing, [Subject("fs", OtherIdentity, Tool("read"), Tool("new"))], PinnedAt).Reports);

        Assert.True(report.IdentityChanged);
        Assert.True(report.HasDifferences);
        Assert.Empty(report.Changed);
        Assert.Equal(PinChange.IdentityChanged, report.ChangeOf("read"));
        Assert.Equal(PinChange.IdentityChanged, report.ChangeOf("new"));
        Assert.Equal("fs-command", report.PinnedHint);
    }

    [Fact]
    public void OnlyNewServers_ArePinned_WhenOthersAlreadyHavePins()
    {
        var existing = PinsDocument.Empty.With("fs", Pinned(Identity, Tool("read")));

        var result = PinCheck.Run(
            existing,
            [Subject("fs", Identity, Tool("read", "changed")), Subject("gh", Identity, Tool("issue"))],
            PinnedAt);

        Assert.Equal(["gh"], result.NewlyPinned);
        Assert.Equal(existing.EffectiveServers["fs"], result.Document.EffectiveServers["fs"]);
        Assert.True(result.Document.EffectiveServers.ContainsKey("gh"));

        // The document the caller passed in is untouched.
        Assert.False(existing.EffectiveServers.ContainsKey("gh"));
    }

    [Fact]
    public void None_IsEmpty()
    {
        Assert.Empty(PinCheckResult.None.Reports);
        Assert.False(PinCheckResult.None.DocumentChanged);
    }

    [Fact]
    public void ADuplicatedToolName_PinsTheLastCopy()
    {
        var pinned = Subject("fs", Identity, Tool("read", "first"), Tool("read", "second")).Pin(PinnedAt);

        Assert.Equal(ToolDefinition.Hash(Tool("read", "second")), pinned.EffectiveTools["read"].Hash);
    }

    [Fact]
    public void Arguments_AreChecked()
    {
        Assert.Throws<ArgumentNullException>(() => PinCheck.Run(null, null!, PinnedAt));
        Assert.Throws<ArgumentNullException>(() => ServerPinReport.Compare(null, null!));
        Assert.Throws<ArgumentNullException>(() => PinSubject.From(null!));
        Assert.Throws<ArgumentNullException>(() => PinsDocument.Empty.With(null!, Pinned()));
        Assert.Throws<ArgumentNullException>(() => PinsDocument.Empty.With("fs", null!));
        Assert.Throws<ArgumentNullException>(() => PinsDocument.Empty.Without(null!));
    }

    [Fact]
    public void Documents_WithoutTheirMaps_ReadAsEmpty()
    {
        Assert.Empty(new PinsDocument().EffectiveServers);
        Assert.Empty(new PinnedServer().EffectiveTools);
        Assert.Empty(new PinsDocument().Without("fs").EffectiveServers);
        Assert.Single(new PinsDocument().With("fs", new PinnedServer()).EffectiveServers);
    }

    // -------------------------------------------------- subjects from connections

    [Fact]
    public async Task ASubject_FromALiveConnection_CarriesItsIdentityAndTools()
    {
        await using var server = InMemoryMcpServer.Start(
            "fixture",
            McpServerTool.Create(() => "ok", new McpServerToolCreateOptions { Name = "ping" }));
        var config = new UpstreamServerConfig { Name = "fs", Command = "npx", Arguments = ["-y", "pkg@1"] };
        await using var registry = await UpstreamRegistry.ConnectAsync(
            [config], NullLoggerFactory.Instance, server.TransportFactory);

        var subject = PinSubject.From(registry.Connections.Single());

        Assert.Equal("fs", subject.Server);
        Assert.Equal(ServerIdentity.Fingerprint(config), subject.Identity);
        Assert.Equal("npx -y pkg@1", subject.IdentityHint);
        Assert.Equal(["ping"], subject.Tools.Select(t => t.Name));
    }

    [Fact]
    public async Task ASubject_FromAConnectionWithoutConfig_IsRefused()
    {
        await using var server = InMemoryMcpServer.Start(
            "fixture",
            McpServerTool.Create(() => "ok", new McpServerToolCreateOptions { Name = "ping" }));
        await using var registry = await UpstreamRegistry.ConnectAsync(
            [new UpstreamServerConfig { Name = "fs", Command = "npx" }], NullLoggerFactory.Instance, server.TransportFactory);
        var bare = registry.Connections.Single() with { Config = null };

        Assert.Throws<ArgumentException>(() => PinSubject.From(bare));
    }
}
