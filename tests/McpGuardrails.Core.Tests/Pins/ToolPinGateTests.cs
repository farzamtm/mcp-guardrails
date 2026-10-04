using McpGuardrails.Core.Pins;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Scanners;
using McpGuardrails.Core.Upstream;
using ModelContextProtocol.Protocol;
using static McpGuardrails.Core.Tests.Pins.PinTestData;

namespace McpGuardrails.Core.Tests.Pins;

/// <summary>
/// Tests for what the client is shown, and may call, when tools differ from
/// their pins - every row of the behaviour table under warn and block.
/// </summary>
public sealed class ToolPinGateTests
{
    private static readonly Decision _allow = new(Verdict.Allow, "allowed", "allow-all");

    /// <summary>fs was pinned with read, write and gone; it now serves read (changed), write and new.</summary>
    private static ServerPinReport Report(string identity = Identity) =>
        ServerPinReport.Compare(
            Pinned(Identity, Tool("read"), Tool("write"), Tool("gone")),
            Subject("fs", identity, Tool("read", "Now with instructions."), Tool("write"), Tool("new")));

    private static Tool[] Advertised() =>
        [.. new[] { Tool("read", "Now with instructions."), Tool("write"), Tool("new") }.Select(t => ToolNamespacer.Qualify("fs", t))];

    private static ToolPinGate Build(PinSettings settings, ServerPinReport? report = null, Tool[]? advertised = null) =>
        ToolPinGate.Build(settings, [report ?? Report()], advertised ?? Advertised());

    private static Tool? Listed(ToolPinGate gate, string name) => gate.Tools.SingleOrDefault(t => t.Name == name);

    [Fact]
    public void Warn_AnnotatesChangedAndNewTools_AndKeepsTheOriginal()
    {
        var gate = Build(PinSettings.Default);

        Assert.StartsWith("[guardrails] WARNING: its definition changed since server 'fs' was pinned on 2026-10-04", Listed(gate, "fs__read")!.Description, StringComparison.Ordinal);
        Assert.EndsWith("--- description from 'fs' ---\nNow with instructions.", Listed(gate, "fs__read")!.Description, StringComparison.Ordinal);
        Assert.Contains("it is new", Listed(gate, "fs__new")!.Description, StringComparison.Ordinal);
        Assert.Equal("Does a thing.", Listed(gate, "fs__write")!.Description);

        Assert.Equal(["fs__read", "fs__new"], gate.Findings.Select(f => f.Tool));
        Assert.All(gate.Findings, f => Assert.Equal(PinEffect.Annotated, f.Effect));
        Assert.Same(_allow, gate.Apply(_allow, "fs__read"));
    }

    [Fact]
    public void Annotating_CopiesTheTool_AndLeavesTheSchemaAlone()
    {
        var advertised = Advertised();
        var gate = Build(PinSettings.Default, advertised: advertised);

        Assert.Equal("Now with instructions.", advertised[0].Description);
        Assert.NotSame(advertised[0], Listed(gate, "fs__read"));
        Assert.Equal(advertised[0].InputSchema.GetRawText(), Listed(gate, "fs__read")!.InputSchema.GetRawText());
        Assert.Same(advertised[1], Listed(gate, "fs__write"));
    }

    [Fact]
    public void AToolWithNoDescription_GetsTheWarningAlone()
    {
        var bare = Tool("read", "Now with instructions.");
        var advertised = ToolNamespacer.Qualify("fs", bare);
        advertised.Description = null;

        var gate = Build(PinSettings.Default, advertised: [advertised]);

        Assert.DoesNotContain("--- description", Listed(gate, "fs__read")!.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void Block_WithholdsChangedTools_AndRefusesCallsToThem()
    {
        var gate = Build(new PinSettings { Mode = PinMode.Block });

        Assert.Null(Listed(gate, "fs__read"));
        Assert.NotNull(Listed(gate, "fs__write"));

        var decision = gate.Apply(_allow, "fs__read");
        Assert.Equal(Verdict.Deny, decision.Verdict);
        Assert.Equal(DecisionSource.Scanner, decision.Source);
        Assert.Equal(ToolPinGate.ChangedRule, decision.RuleName);
        Assert.Contains("pins diff fs read", decision.Reason, StringComparison.Ordinal);
        Assert.Contains("pins accept", decision.ToModelMessage(), StringComparison.Ordinal);
        Assert.Same(_allow, gate.Apply(_allow, "fs__write"));
    }

    [Theory]
    [InlineData(NewToolAction.Warn, PinEffect.Annotated, true)]
    [InlineData(NewToolAction.Block, PinEffect.Blocked, false)]
    [InlineData(NewToolAction.Allow, PinEffect.Allowed, true)]
    public void NewTools_FollowOnNewTool(NewToolAction action, PinEffect effect, bool listed)
    {
        var gate = Build(new PinSettings { Mode = PinMode.Block, OnNewTool = action });

        Assert.Equal(effect, gate.Findings.Single(f => f.Tool == "fs__new").Effect);
        Assert.Equal(listed, Listed(gate, "fs__new") is not null);

        if (action is NewToolAction.Allow)
        {
            Assert.Equal("Does a thing.", Listed(gate, "fs__new")!.Description);
        }

        if (action is NewToolAction.Block)
        {
            Assert.Equal(ToolPinGate.NewToolRule, gate.Apply(_allow, "fs__new").RuleName);
        }
    }

    [Fact]
    public void AChangedIdentity_FlagsEveryTool_RegardlessOfOnNewTool()
    {
        var gate = Build(new PinSettings { Mode = PinMode.Block, OnNewTool = NewToolAction.Allow }, Report(OtherIdentity));

        Assert.Empty(gate.Tools);
        Assert.All(gate.Findings, f => Assert.Equal(PinChange.IdentityChanged, f.Change));
        Assert.Equal(ToolPinGate.ChangedRule, gate.Apply(_allow, "fs__new").RuleName);
        Assert.Contains("no longer the program", gate.Apply(_allow, "fs__write").Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Off_FlagsNothing_WhateverItIsGiven()
    {
        var gate = Build(PinSettings.Disabled);

        Assert.Empty(gate.Findings);
        Assert.Equal(Advertised().Select(t => t.Name), gate.Tools.Select(t => t.Name));
    }

    [Fact]
    public void AFirstSeenServer_IsNotFlagged()
    {
        var report = ServerPinReport.Compare(null, Subject("fs", Identity, Tool("read")));

        Assert.Empty(Build(new PinSettings { Mode = PinMode.Block }, report).Findings);
    }

    [Fact]
    public void APolicyDenial_IsKeptAsTheOperatorWroteIt()
    {
        var gate = Build(new PinSettings { Mode = PinMode.Block });
        var denied = new Decision(Verdict.Deny, "Reads are off limits.", "no-reads");

        Assert.Same(denied, gate.Apply(denied, "fs__read"));
    }

    [Fact]
    public void AMetadataDenial_IsExtended_SoTheRefusalNamesBothReasons()
    {
        var gate = Build(new PinSettings { Mode = PinMode.Block });
        var metadata = _allow.RefusedBy(DecisionSource.Scanner, ToolMetadataGate.MetadataRule, "Looks poisoned.", "trail") with
        {
            Trail = ["policy: allow"],
        };

        var decision = gate.Apply(metadata, "fs__read");

        Assert.Equal($"{ToolMetadataGate.MetadataRule}, {ToolPinGate.ChangedRule}", decision.RuleName);
        Assert.StartsWith("Looks poisoned. Separately, this tool was withheld", decision.Reason, StringComparison.Ordinal);
        Assert.Equal(["policy: allow", "scanner 'pins': changed -> deny"], decision.Trail);
    }

    [Fact]
    public void AScannerDenialFromAnotherGate_IsKept()
    {
        var gate = Build(new PinSettings { Mode = PinMode.Block });
        var secrets = _allow.RefusedBy(DecisionSource.Scanner, "secrets.arguments", "Has a key.", "trail");

        Assert.Same(secrets, gate.Apply(secrets, "fs__read"));
    }

    [Fact]
    public void ARequireApprovalVerdict_IsRefusedBeforeAnyoneIsAsked()
    {
        var gate = Build(new PinSettings { Mode = PinMode.Block });

        var decision = gate.Apply(new Decision(Verdict.RequireApproval, "ask", "approve"), "fs__read");

        Assert.Equal(Verdict.Deny, decision.Verdict);
    }

    [Fact]
    public void APinWithNoDate_IsExplainedWithoutOne()
    {
        var report = Report() with { PinnedAt = null };

        var finding = Build(PinSettings.Default, report).Findings.First();

        Assert.Equal("its definition changed since server 'fs' was pinned", finding.Explain());
    }

    [Fact]
    public void Findings_DescribeThemselvesInTheAuditLogsWords()
    {
        var finding = new ToolPinFinding("fs__x", "fs", "x", PinChange.Changed, PinEffect.Annotated, Report());

        Assert.Equal("changed", finding.DescribeChange());
        Assert.Equal("added", (finding with { Change = PinChange.Added }).DescribeChange());
        Assert.Equal("identity_changed", (finding with { Change = PinChange.IdentityChanged }).DescribeChange());
        Assert.Equal("annotated", finding.DescribeEffect());
        Assert.Equal("blocked", (finding with { Effect = PinEffect.Blocked }).DescribeEffect());
        Assert.Equal("allowed", (finding with { Effect = PinEffect.Allowed }).DescribeEffect());
    }

    [Fact]
    public void Arguments_AreChecked()
    {
        Assert.Throws<ArgumentNullException>(() => ToolPinGate.Build(null!, [], []));
        Assert.Throws<ArgumentNullException>(() => ToolPinGate.Build(PinSettings.Default, null!, []));
        Assert.Throws<ArgumentNullException>(() => ToolPinGate.Build(PinSettings.Default, [], null!));

        var gate = Build(PinSettings.Default);
        Assert.Throws<ArgumentNullException>(() => gate.Apply(null!, "fs__read"));
        Assert.Throws<ArgumentNullException>(() => gate.Apply(_allow, null!));
    }

    // ----------------------------------------------------------------- audit

    [Fact]
    public void Audit_RecordsNamesAndVerdicts()
    {
        var at = PinnedAt;
        var report = Report();
        var finding = Build(PinSettings.Default).Findings.First();

        var created = PinAudit.Created(ServerPinReport.Compare(null, Subject("fs", Identity, Tool("read"))), at);
        Assert.Equal(("pin_created", "fs", 1, "fs-command"), (created.Event, created.Server, created.ToolCount, created.Identity));
        Assert.Null(created.Tool);

        var changed = PinAudit.Changed(finding, at);
        Assert.Equal(("pin_changed", "fs__read", "read", "changed", "annotated"), (changed.Event, changed.Tool, changed.DownstreamTool, changed.PinChange, changed.ScannerAction));
        Assert.Null(changed.Identity);

        var moved = PinAudit.Changed(finding with { Change = PinChange.IdentityChanged }, at);
        Assert.Equal("fs-command", moved.Identity);

        var removed = Assert.Single(PinAudit.Removed(report, at));
        Assert.Equal(("pin_removed", "fs__gone"), (removed.Event, removed.Tool));

        var accepted = PinAudit.Accepted("fs", new AcceptedPin("read", false), at);
        Assert.Equal(("pin_accepted", "fs__read"), (accepted.Event, accepted.Tool));
        Assert.Null(accepted.PinChange);
        Assert.Equal("removed", PinAudit.Accepted("fs", new AcceptedPin("gone", true), at).PinChange);

        var reset = PinAudit.Reset("fs", at);
        Assert.Equal(("pin_reset", "fs", null), (reset.Event, reset.Server, reset.Tool));
        Assert.False(reset.IsError);
    }

    [Fact]
    public void Audit_ChecksItsArguments()
    {
        Assert.Throws<ArgumentNullException>(() => PinAudit.Created(null!, PinnedAt));
        Assert.Throws<ArgumentNullException>(() => PinAudit.Changed(null!, PinnedAt));
        Assert.Throws<ArgumentNullException>(() => PinAudit.Removed(null!, PinnedAt));
        Assert.Throws<ArgumentNullException>(() => PinAudit.Accepted(null!, new AcceptedPin("x", false), PinnedAt));
        Assert.Throws<ArgumentNullException>(() => PinAudit.Accepted("fs", null!, PinnedAt));
        Assert.Throws<ArgumentNullException>(() => PinAudit.Reset(null!, PinnedAt));
    }
}
