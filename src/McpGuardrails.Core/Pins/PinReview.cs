using System.Text;
using System.Text.Json;
using McpGuardrails.Core.Serialization;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Pins;

/// <summary>What <c>pins accept</c> did to one tool.</summary>
/// <param name="Tool">The tool, under the server's own name for it.</param>
/// <param name="Removed">True when the tool was no longer served and its pin was dropped.</param>
public sealed record AcceptedPin(string Tool, bool Removed);

/// <summary>
/// The explicit side of pinning: looking at what changed, and accepting it.
/// </summary>
/// <remarks>
/// Pure functions over documents and subjects, so the commands that call them
/// are only wiring and every rule here is tested.
/// </remarks>
public static class PinReview
{
    /// <summary>Re-pins a whole server: its identity and every tool it serves now.</summary>
    /// <returns>The new document, and every tool whose pin changed.</returns>
    public static (PinsDocument Document, IReadOnlyList<AcceptedPin> Accepted) AcceptServer(
        PinsDocument document, PinSubject subject, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(subject);

        document.EffectiveServers.TryGetValue(subject.Server, out var pinned);
        var report = ServerPinReport.Compare(pinned, subject);

        var accepted = report.FirstSeen || report.IdentityChanged
            ? report.Current.Select(tool => new AcceptedPin(tool, Removed: false))
            : report.Changed.Concat(report.Added).Select(tool => new AcceptedPin(tool, Removed: false));

        return (
            document.With(subject.Server, subject.Pin(now)),
            [.. accepted, .. report.Removed.Select(tool => new AcceptedPin(tool, Removed: true))]);
    }

    /// <summary>Re-pins only the named tools of a server whose identity is unchanged.</summary>
    /// <exception cref="PinsException">
    /// The server has no pins or a changed identity, or a name is neither served nor pinned.
    /// </exception>
    /// <remarks>
    /// A changed identity cannot be accepted one tool at a time. The identity is
    /// what says the other tools are still the reviewed ones; keeping the old
    /// identity would leave every tool flagged, and adopting the new one would
    /// vouch for tools nobody named.
    /// </remarks>
    public static (PinsDocument Document, IReadOnlyList<AcceptedPin> Accepted) AcceptTools(
        PinsDocument document, PinSubject subject, IReadOnlyList<string> tools, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(tools);

        if (!document.EffectiveServers.TryGetValue(subject.Server, out var pinned))
        {
            throw new PinsException(
                $"Server '{subject.Server}' has no pins yet. Run 'pins accept {subject.Server}' to pin all of its tools.");
        }

        if (!string.Equals(pinned.Identity, subject.Identity, StringComparison.Ordinal))
        {
            throw new PinsException(
                $"Server '{subject.Server}' is a different program from the one it was pinned from " +
                $"('{pinned.IdentityHint}', now '{subject.IdentityHint}'). Its tools cannot be accepted one by one; " +
                $"review 'pins diff {subject.Server}' and run 'pins accept {subject.Server}' to accept the whole server.");
        }

        var pins = new SortedDictionary<string, PinnedTool>(
            pinned.EffectiveTools.ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal),
            StringComparer.Ordinal);
        var accepted = new List<AcceptedPin>();

        foreach (var name in tools)
        {
            if (subject.Tools.LastOrDefault(tool => tool.Name == name) is { } served)
            {
                pins[name] = PinSubject.PinTool(served);
                accepted.Add(new AcceptedPin(name, Removed: false));
            }
            else if (pins.Remove(name))
            {
                accepted.Add(new AcceptedPin(name, Removed: true));
            }
            else
            {
                throw new PinsException(
                    $"Server '{subject.Server}' neither serves nor has a pin for a tool named '{name}'.");
            }
        }

        return (document.With(subject.Server, pinned with { PinnedAt = now, Tools = pins }), accepted);
    }

    /// <summary>Forgets a server, so it is pinned afresh on the next start.</summary>
    /// <exception cref="PinsException">The server has no pins.</exception>
    public static PinsDocument Reset(PinsDocument document, string server)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(server);

        return document.EffectiveServers.ContainsKey(server)
            ? document.Without(server)
            : throw new PinsException($"Server '{server}' has no pins to reset.");
    }

    /// <summary>
    /// A readable diff of a server's pinned definitions against what it serves now.
    /// </summary>
    /// <param name="pinned">The server's pins, or null when it has none.</param>
    /// <param name="subject">What it serves now.</param>
    /// <param name="tool">One tool to show, or null for every difference.</param>
    /// <exception cref="PinsException">The named tool is neither served nor pinned.</exception>
    /// <remarks>
    /// The definitions are shown in canonical form, one value per line, so two
    /// definitions that hash the same print the same, and a reordered schema
    /// never shows up as a change.
    /// </remarks>
    public static string Diff(PinnedServer? pinned, PinSubject subject, string? tool)
    {
        ArgumentNullException.ThrowIfNull(subject);

        var report = ServerPinReport.Compare(pinned, subject);
        var output = new StringBuilder();

        if (pinned is null)
        {
            return $"Server '{subject.Server}' has no pins yet; it will be pinned on its next start.\n";
        }

        if (report.IdentityChanged)
        {
            output.Append($"Server '{subject.Server}' is a different program from the one it was pinned from.\n")
                .Append($"  pinned from: {report.PinnedHint}\n")
                .Append($"  now:         {report.CurrentHint}\n\n");
        }

        var names = tool is null
            ? report.Changed.Concat(report.Added).Concat(report.Removed).ToList()
            : [tool];

        if (tool is not null &&
            !report.Current.Contains(tool, StringComparer.Ordinal) &&
            !pinned.EffectiveTools.ContainsKey(tool))
        {
            throw new PinsException($"Server '{subject.Server}' neither serves nor has a pin for a tool named '{tool}'.");
        }

        if (names.Count == 0 && !report.IdentityChanged)
        {
            return $"Server '{subject.Server}' serves exactly what was pinned.\n";
        }

        foreach (var name in names)
        {
            var served = subject.Tools.LastOrDefault(t => t.Name == name);
            pinned.EffectiveTools.TryGetValue(name, out var pin);

            var (label, before, after) = (pin, served) switch
            {
                (null, { } now) => ("added", string.Empty, Format(ToolDefinition.Canonical(now))),
                ({ } old, null) => ("removed", Stored(old), string.Empty),
                ({ } old, { } now) when report.Changed.Contains(name, StringComparer.Ordinal) =>
                    ("changed", Stored(old), Format(ToolDefinition.Canonical(now))),
                _ => ("unchanged", string.Empty, string.Empty),
            };

            output.Append($"--- {subject.Server} / {name} ({label})\n");
            if (label != "unchanged")
            {
                output.Append(LineDiff.Format(before, after));
            }

            output.Append('\n');
        }

        return output.ToString();
    }

    /// <summary>The pinned copy of a definition, laid out for a diff.</summary>
    /// <exception cref="PinsException">The stored copy does not decode to JSON.</exception>
    private static string Stored(PinnedTool pin)
    {
        if (pin.Definition is not { } definition)
        {
            return "(no stored copy of the pinned definition, only its hash)";
        }

        try
        {
            return Format(PinsFile.Decompress(definition));
        }
        catch (JsonException ex)
        {
            throw new PinsException($"The stored definition is corrupt: {ex.Message}", ex);
        }
    }

    private static string Format(string canonical)
    {
        using var document = JsonDocument.Parse(canonical);
        return CanonicalJson.Format(document.RootElement);
    }
}
