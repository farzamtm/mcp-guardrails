using McpGuardrails.Core.Upstream;
using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Pins;

/// <summary>One connected server, as pinning sees it.</summary>
/// <param name="Server">The server's configured name.</param>
/// <param name="Identity">Its <see cref="ServerIdentity.Fingerprint"/>.</param>
/// <param name="IdentityHint">Its <see cref="ServerIdentity.Hint"/>.</param>
/// <param name="Tools">The definitions it advertised, under its own tool names.</param>
public sealed record PinSubject(string Server, string Identity, string IdentityHint, IReadOnlyList<Tool> Tools)
{
    /// <summary>The subject for a live connection.</summary>
    /// <exception cref="ArgumentException">The connection does not carry the config it was made from.</exception>
    public static PinSubject From(UpstreamConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);

        // The registry always records the config; a hand-built connection without
        // one has no identity, and inventing one would make every comparison
        // against a real pin report a changed identity.
        var config = connection.Config
                     ?? throw new ArgumentException(
                         $"Connection '{connection.Name}' has no config to take an identity from.", nameof(connection));

        return new PinSubject(
            connection.Name,
            ServerIdentity.Fingerprint(config),
            ServerIdentity.Hint(config),
            [.. connection.Tools.Select(tool => tool.ProtocolTool)]);
    }

    /// <summary>The pins this server would get if it were pinned now.</summary>
    public PinnedServer Pin(DateTimeOffset now)
    {
        // Assigned rather than added, so a server that advertises one name twice
        // pins the copy the registry routes to - the last - instead of failing
        // to start. The comparison then flags whichever copy differs.
        var tools = new SortedDictionary<string, PinnedTool>(StringComparer.Ordinal);
        foreach (var tool in Tools)
        {
            tools[tool.Name] = PinTool(tool);
        }

        return new PinnedServer
        {
            Identity = Identity,
            IdentityHint = IdentityHint,
            PinnedAt = now,
            Tools = tools,
        };
    }

    /// <summary>The pin for one of this server's tools.</summary>
    public static PinnedTool PinTool(Tool tool)
    {
        var canonical = ToolDefinition.Canonical(tool);
        return new PinnedTool
        {
            Hash = Serialization.CanonicalJson.HashText(canonical),
            Definition = PinsFile.Compress(canonical),
        };
    }
}

/// <summary>Why a tool is not what was pinned.</summary>
public enum PinChange
{
    /// <summary>Its definition hashes differently.</summary>
    Changed,

    /// <summary>It was not there when the server was pinned.</summary>
    Added,

    /// <summary>
    /// The server name now stands for a different program, so none of its tools
    /// can be vouched for, whatever their hashes say.
    /// </summary>
    IdentityChanged,
}

/// <summary>How one server's tools compare with its pins.</summary>
public sealed record ServerPinReport
{
    /// <summary>The server's configured name.</summary>
    public required string Server { get; init; }

    /// <summary>True when the server had no pins, and was trusted on first use.</summary>
    public bool FirstSeen { get; init; }

    /// <summary>True when the server's identity differs from the pinned one.</summary>
    public bool IdentityChanged { get; init; }

    /// <summary>What the server was pinned from, when it had pins.</summary>
    public string? PinnedHint { get; init; }

    /// <summary>The identity it has now.</summary>
    public required string CurrentHint { get; init; }

    /// <summary>When it was pinned, when it had pins.</summary>
    public DateTimeOffset? PinnedAt { get; init; }

    /// <summary>Every tool it advertises now, in advertised order.</summary>
    public IReadOnlyList<string> Current { get; init; } = [];

    /// <summary>Tools whose definition differs from the pin, in advertised order.</summary>
    public IReadOnlyList<string> Changed { get; init; } = [];

    /// <summary>Tools that have no pin, in advertised order.</summary>
    public IReadOnlyList<string> Added { get; init; } = [];

    /// <summary>Pinned tools the server no longer advertises, in ordinal order.</summary>
    public IReadOnlyList<string> Removed { get; init; } = [];

    /// <summary>True when anything is not exactly as pinned, including not being pinned at all.</summary>
    public bool HasDifferences =>
        FirstSeen || IdentityChanged || Changed.Count > 0 || Added.Count > 0 || Removed.Count > 0;

    /// <summary>Why <paramref name="tool"/> is not as pinned, or null when it is.</summary>
    /// <remarks>
    /// A changed identity outranks the tool's own hash: a different program that
    /// happens to serve an identical definition today is still not the program
    /// that was reviewed.
    /// </remarks>
    public PinChange? ChangeOf(string tool)
    {
        if (FirstSeen || !Current.Contains(tool, StringComparer.Ordinal))
        {
            return null;
        }

        if (IdentityChanged)
        {
            return PinChange.IdentityChanged;
        }

        if (Changed.Contains(tool, StringComparer.Ordinal))
        {
            return PinChange.Changed;
        }

        return Added.Contains(tool, StringComparer.Ordinal) ? PinChange.Added : null;
    }

    /// <summary>Compares one server with its pins.</summary>
    /// <param name="pinned">The server's pins, or null when it has none.</param>
    /// <param name="subject">What it advertises now.</param>
    public static ServerPinReport Compare(PinnedServer? pinned, PinSubject subject)
    {
        ArgumentNullException.ThrowIfNull(subject);

        var current = subject.Tools.Select(tool => tool.Name).ToList();

        if (pinned is null)
        {
            return new ServerPinReport
            {
                Server = subject.Server,
                FirstSeen = true,
                CurrentHint = subject.IdentityHint,
                Current = current,
            };
        }

        var pins = pinned.EffectiveTools;
        var changed = new List<string>();
        var added = new List<string>();

        foreach (var tool in subject.Tools)
        {
            if (!pins.TryGetValue(tool.Name, out var pin))
            {
                added.Add(tool.Name);
            }
            else if (!string.Equals(pin.Hash, ToolDefinition.Hash(tool), StringComparison.Ordinal))
            {
                changed.Add(tool.Name);
            }
        }

        return new ServerPinReport
        {
            Server = subject.Server,
            IdentityChanged = !string.Equals(pinned.Identity, subject.Identity, StringComparison.Ordinal),
            PinnedHint = pinned.IdentityHint,
            CurrentHint = subject.IdentityHint,
            PinnedAt = pinned.PinnedAt,
            Current = current,
            Changed = changed,
            Added = added,
            Removed = [.. pins.Keys.Where(name => !current.Contains(name, StringComparer.Ordinal)).Order(StringComparer.Ordinal)],
        };
    }
}

/// <summary>The outcome of comparing every connected server with the pins file.</summary>
/// <param name="Document">The pins, with every first-seen server added.</param>
/// <param name="NewlyPinned">The servers trusted on first use, in connection order.</param>
/// <param name="Reports">One report per server, in connection order.</param>
public sealed record PinCheckResult(
    PinsDocument Document,
    IReadOnlyList<string> NewlyPinned,
    IReadOnlyList<ServerPinReport> Reports)
{
    /// <summary>Nothing compared: pinning is off.</summary>
    public static PinCheckResult None { get; } = new(PinsDocument.Empty, [], []);

    /// <summary>True when the document has servers it did not have before and should be saved.</summary>
    public bool DocumentChanged => NewlyPinned.Count > 0;
}

/// <summary>Compares every connected server with the pins file.</summary>
public static class PinCheck
{
    /// <summary>
    /// Compares, and pins every server that has never been seen.
    /// </summary>
    /// <param name="existing">The pins file, or null when there is none yet.</param>
    /// <param name="subjects">The connected servers.</param>
    /// <param name="now">The time recorded for new pins.</param>
    /// <remarks>
    /// The only automatic write pinning ever makes is this one: trust on first
    /// use. A server that already has pins is never re-pinned here, whatever it
    /// serves - that takes <c>pins accept</c>, a person's explicit decision.
    /// </remarks>
    public static PinCheckResult Run(PinsDocument? existing, IEnumerable<PinSubject> subjects, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(subjects);

        var document = existing ?? PinsDocument.Empty;
        var reports = new List<ServerPinReport>();
        var newlyPinned = new List<string>();

        foreach (var subject in subjects)
        {
            document.EffectiveServers.TryGetValue(subject.Server, out var pinned);
            var report = ServerPinReport.Compare(pinned, subject);
            reports.Add(report);

            if (report.FirstSeen)
            {
                document = document.With(subject.Server, subject.Pin(now));
                newlyPinned.Add(subject.Server);
            }
        }

        return new PinCheckResult(document, newlyPinned, reports);
    }
}
