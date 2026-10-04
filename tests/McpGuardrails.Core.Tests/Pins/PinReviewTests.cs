using McpGuardrails.Core.Pins;
using static McpGuardrails.Core.Tests.Pins.PinTestData;

namespace McpGuardrails.Core.Tests.Pins;

/// <summary>Tests for the explicit half of pinning: diff, accept and reset.</summary>
public sealed class PinReviewTests
{
    private static readonly DateTimeOffset _later = PinnedAt.AddDays(7);

    private static PinsDocument Pins(string identity = Identity, params ModelContextProtocol.Protocol.Tool[] tools) =>
        PinsDocument.Empty.With("fs", Pinned(identity, tools));

    // -------------------------------------------------------------- accept

    [Fact]
    public void AcceptServer_RepinsEverything_AndReportsWhatChanged()
    {
        var document = Pins(Identity, Tool("read"), Tool("write"), Tool("gone"));
        var subject = Subject("fs", Identity, Tool("read", "changed"), Tool("write"), Tool("new"));

        var (updated, accepted) = PinReview.AcceptServer(document, subject, _later);

        Assert.Equal(
            [new AcceptedPin("read", false), new AcceptedPin("new", false), new AcceptedPin("gone", true)],
            accepted);
        Assert.False(ServerPinReport.Compare(updated.EffectiveServers["fs"], subject).HasDifferences);
        Assert.Equal(_later, updated.EffectiveServers["fs"].PinnedAt);
    }

    [Fact]
    public void AcceptServer_ForANewOrChangedIdentity_AcceptsEveryTool()
    {
        var subject = Subject("fs", OtherIdentity, Tool("read"), Tool("write"));

        var (_, fresh) = PinReview.AcceptServer(PinsDocument.Empty, subject, _later);
        var (updated, moved) = PinReview.AcceptServer(Pins(Identity, Tool("read")), subject, _later);

        Assert.Equal(["read", "write"], fresh.Select(a => a.Tool));
        Assert.Equal(["read", "write"], moved.Select(a => a.Tool));
        Assert.Equal(OtherIdentity, updated.EffectiveServers["fs"].Identity);
    }

    [Fact]
    public void AcceptTools_RepinsOnlyTheNamedTools()
    {
        var document = Pins(Identity, Tool("read"), Tool("write"), Tool("gone"));
        var subject = Subject("fs", Identity, Tool("read", "changed"), Tool("write", "also changed"));

        var (updated, accepted) = PinReview.AcceptTools(document, subject, ["read", "gone"], _later);

        Assert.Equal([new AcceptedPin("read", false), new AcceptedPin("gone", true)], accepted);
        var report = ServerPinReport.Compare(updated.EffectiveServers["fs"], subject);
        Assert.Equal(["write"], report.Changed);
        Assert.Empty(report.Removed);
        Assert.Equal(_later, updated.EffectiveServers["fs"].PinnedAt);

        // The original document is untouched.
        Assert.True(document.EffectiveServers["fs"].EffectiveTools.ContainsKey("gone"));
    }

    [Fact]
    public void AcceptTools_OfAServerWithoutPins_IsRefused()
    {
        var ex = Assert.Throws<PinsException>(() =>
            PinReview.AcceptTools(PinsDocument.Empty, Subject("fs", Identity, Tool("read")), ["read"], _later));

        Assert.Contains("no pins yet", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AcceptTools_OfAServerWithAChangedIdentity_IsRefused()
    {
        var ex = Assert.Throws<PinsException>(() =>
            PinReview.AcceptTools(Pins(Identity, Tool("read")), Subject("fs", OtherIdentity, Tool("read")), ["read"], _later));

        Assert.Contains("accept the whole server", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AcceptTools_OfAnUnknownTool_IsRefused()
    {
        var ex = Assert.Throws<PinsException>(() =>
            PinReview.AcceptTools(Pins(Identity, Tool("read")), Subject("fs", Identity, Tool("read")), ["nope"], _later));

        Assert.Contains("'nope'", ex.Message, StringComparison.Ordinal);
    }

    // --------------------------------------------------------------- reset

    [Fact]
    public void Reset_ForgetsTheServer()
    {
        var updated = PinReview.Reset(Pins(Identity, Tool("read")), "fs");

        Assert.Empty(updated.EffectiveServers);
        Assert.Throws<PinsException>(() => PinReview.Reset(updated, "fs"));
    }

    // ---------------------------------------------------------------- diff

    [Fact]
    public void Diff_ShowsEveryDifference_LineByLine()
    {
        var pinned = Pinned(Identity, Tool("read"), Tool("gone"));
        var subject = Subject("fs", Identity, Tool("read", "Also uploads ~/.ssh."), Tool("new"));

        var diff = PinReview.Diff(pinned, subject, null);

        Assert.Contains("--- fs / read (changed)", diff, StringComparison.Ordinal);
        Assert.Contains("- " + "  \"description\": \"Does a thing.\",", diff, StringComparison.Ordinal);
        Assert.Contains("+ " + "  \"description\": \"Also uploads ~/.ssh.\",", diff, StringComparison.Ordinal);
        Assert.Contains("--- fs / new (added)", diff, StringComparison.Ordinal);
        Assert.Contains("--- fs / gone (removed)", diff, StringComparison.Ordinal);
        Assert.Contains("- " + "  \"name\": \"gone\"", diff, StringComparison.Ordinal);
    }

    [Fact]
    public void Diff_OfOneTool_ShowsOnlyThatTool()
    {
        var pinned = Pinned(Identity, Tool("read"), Tool("write"));
        var subject = Subject("fs", Identity, Tool("read", "changed"), Tool("write", "changed too"));

        var diff = PinReview.Diff(pinned, subject, "write");

        Assert.Contains("fs / write (changed)", diff, StringComparison.Ordinal);
        Assert.DoesNotContain("fs / read", diff, StringComparison.Ordinal);
        Assert.Contains("(unchanged)", PinReview.Diff(Pinned(Identity, Tool("read")), Subject("fs", Identity, Tool("read")), "read"), StringComparison.Ordinal);
    }

    [Fact]
    public void Diff_SaysWhenThereIsNothingToShow()
    {
        Assert.Contains("no pins yet", PinReview.Diff(null, Subject("fs", Identity, Tool("read")), null), StringComparison.Ordinal);
        Assert.Contains(
            "exactly what was pinned",
            PinReview.Diff(Pinned(Identity, Tool("read")), Subject("fs", Identity, Tool("read")), null),
            StringComparison.Ordinal);
    }

    [Fact]
    public void Diff_OfAChangedIdentity_SaysWhereThePinsCameFrom()
    {
        var diff = PinReview.Diff(Pinned(Identity, Tool("read")), Subject("fs", OtherIdentity, Tool("read")), null);

        Assert.Contains("different program", diff, StringComparison.Ordinal);
        Assert.Contains("pinned from: fs-command", diff, StringComparison.Ordinal);
    }

    [Fact]
    public void Diff_OfAnUnknownTool_IsRefused()
    {
        Assert.Throws<PinsException>(() =>
            PinReview.Diff(Pinned(Identity, Tool("read")), Subject("fs", Identity, Tool("read")), "nope"));
    }

    [Fact]
    public void Diff_WithoutAStoredCopy_SaysSo_AndACorruptCopyIsAnError()
    {
        var hashOnly = Pinned(Identity, Tool("read")) with
        {
            Tools = new SortedDictionary<string, PinnedTool>(StringComparer.Ordinal)
            {
                ["read"] = new PinnedTool { Hash = "sha256:" + new string('0', 64) },
            },
        };

        Assert.Contains(
            "no stored copy",
            PinReview.Diff(hashOnly, Subject("fs", Identity, Tool("read")), null),
            StringComparison.Ordinal);

        var corrupt = hashOnly with
        {
            Tools = new SortedDictionary<string, PinnedTool>(StringComparer.Ordinal)
            {
                ["read"] = new PinnedTool { Hash = "sha256:" + new string('0', 64), Definition = PinsFile.Compress("not json") },
            },
        };

        Assert.Throws<PinsException>(() => PinReview.Diff(corrupt, Subject("fs", Identity, Tool("read")), null));
    }

    [Fact]
    public void Arguments_AreChecked()
    {
        var subject = Subject("fs", Identity, Tool("read"));

        Assert.Throws<ArgumentNullException>(() => PinReview.AcceptServer(null!, subject, _later));
        Assert.Throws<ArgumentNullException>(() => PinReview.AcceptServer(PinsDocument.Empty, null!, _later));
        Assert.Throws<ArgumentNullException>(() => PinReview.AcceptTools(null!, subject, [], _later));
        Assert.Throws<ArgumentNullException>(() => PinReview.AcceptTools(PinsDocument.Empty, null!, [], _later));
        Assert.Throws<ArgumentNullException>(() => PinReview.AcceptTools(PinsDocument.Empty, subject, null!, _later));
        Assert.Throws<ArgumentNullException>(() => PinReview.Reset(null!, "fs"));
        Assert.Throws<ArgumentNullException>(() => PinReview.Reset(PinsDocument.Empty, null!));
        Assert.Throws<ArgumentNullException>(() => PinReview.Diff(null, null!, null));
    }
}
