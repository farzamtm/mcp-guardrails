using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Serialization;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Packs;

/// <summary>
/// A ready-made set of policy rules for one popular MCP server, written against
/// a placeholder server name.
/// </summary>
/// <remarks>
/// A pack file has three parts, in this order, and nothing else:
///
/// <code>
/// # Pack: github - what it protects, what it allows, the threat.   (header comment)
/// pack:                                                            (metadata)
///   name: github
///   version: 1
///   description: ...
///   recognizes: [github-mcp-server]
/// rules:                                                           (rules, last)
///   - name: "{{server}}-reads"
///     match: { server: "{{server}}", annotations: { readOnlyHint: true } }
///     decision: allow
/// </code>
///
/// <c>init</c> copies the header and the rules into the user's policy as text,
/// not through a serializer, so every comment explaining a rule survives into
/// the file the user reviews. That is why the layout is strict: the rules block
/// is cut out by line, so it has to be last and indented.
///
/// Every rule must be scoped with <c>server: "{{server}}"</c>. That makes a
/// pack's rules unable to match another server's tools, so packs can be
/// concatenated in any order without one changing another's meaning - in a
/// first-match-wins policy, order is otherwise the whole meaning.
/// </remarks>
public sealed class PolicyPack
{
    /// <summary>What every pack writes where the server's name goes.</summary>
    public const string Placeholder = "{{server}}";

    /// <summary>The server name packs are checked with when they load.</summary>
    /// <remarks>Any valid name works; this one reads well in error messages.</remarks>
    private const string _sampleServer = "example";

    private PolicyPack(PackHeader header, string comment, IReadOnlyList<string> ruleLines)
    {
        Name = header.Name!;
        Version = header.Version!.Value;
        Description = header.Description!;
        Recognizes = header.Recognizes ?? [];
        Comment = comment;
        _ruleLines = ruleLines;
    }

    private readonly IReadOnlyList<string> _ruleLines;

    /// <summary>The pack's name, e.g. <c>github</c>, as given to <c>--pack</c>.</summary>
    public string Name { get; }

    /// <summary>Bumped whenever the rules change meaning, so a diff has a reason attached.</summary>
    public int Version { get; }

    /// <summary>One line for <c>init --list</c>.</summary>
    public string Description { get; }

    /// <summary>
    /// Package, image, binary names and URL prefixes that identify the server
    /// this pack is for; see <see cref="Recognize"/>.
    /// </summary>
    public IReadOnlyList<string> Recognizes { get; }

    /// <summary>The header comment, each line still starting with <c>#</c>.</summary>
    public string Comment { get; }

    /// <summary>
    /// Parses and checks a pack, including that its rules load as a policy and
    /// are all scoped to the placeholder server.
    /// </summary>
    /// <exception cref="PackException">The pack is malformed.</exception>
    public static PolicyPack Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var lines = text.ReplaceLineEndings("\n").Split('\n');

        var commentLines = lines
            .TakeWhile(line => line.StartsWith('#') || string.IsNullOrWhiteSpace(line))
            .ToList();
        var comment = string.Join('\n', commentLines.Where(line => line.StartsWith('#')));
        if (comment.Length == 0)
        {
            throw new PackException(
                "A pack starts with a comment saying what it protects, what it allows " +
                "and the threat it addresses.");
        }

        var rulesIndex = Array.IndexOf(lines, "rules:");
        if (rulesIndex < 0)
        {
            throw new PackException("A pack needs a top-level 'rules:' line.");
        }

        // Trailing blank lines dropped, so packs compose with exactly one blank
        // line between them.
        var ruleLines = Enumerable.Reverse(lines[(rulesIndex + 1)..]).SkipWhile(string.IsNullOrWhiteSpace).Reverse().ToList();

        // Cut out by line, so anything after the block that is not part of it
        // would be copied into the user's policy as if it were.
        if (ruleLines.FirstOrDefault(line => line.Length > 0 && !line.StartsWith("  ", StringComparison.Ordinal))
            is { } stray)
        {
            throw new PackException(
                $"'rules:' must be the last section of a pack, with every line under it " +
                $"indented; found '{stray}'.");
        }

        var root = ParseRoot(text);
        var header = ReadHeader(root);
        var pack = new PolicyPack(header, comment, ruleLines);

        // Rendered once with a sample name, so a broken pack fails here, where
        // its author is, rather than in somebody's init.
        CheckScoped(pack.Name, pack.RenderPolicy(_sampleServer), _sampleServer);

        return pack;
    }

    /// <summary>
    /// True when <paramref name="text"/> looks like a pack rather than a policy:
    /// it has a top-level <c>pack:</c> key.
    /// </summary>
    public static bool IsPack(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        return text.ReplaceLineEndings("\n").Split('\n').Contains("pack:");
    }

    /// <summary>
    /// The pack's rules, with the placeholder replaced by <paramref name="server"/>,
    /// as lines indented to sit under a <c>rules:</c> key.
    /// </summary>
    /// <exception cref="PackException">The name is not a valid server name.</exception>
    public IReadOnlyList<string> RenderRules(string server)
    {
        // Substituted as text into YAML, so the name has to be one that cannot
        // change the document's structure - which the server-name rule (letters,
        // digits, hyphens) already guarantees.
        if (string.IsNullOrEmpty(server) || !UpstreamServerConfig.IsValidName(server))
        {
            throw new PackException(
                $"'{server}' is not a valid server name: use letters, digits and hyphens.");
        }

        return [.. _ruleLines.Select(line => line.Replace(Placeholder, server, StringComparison.Ordinal))];
    }

    /// <summary>
    /// The pack as a standalone policy for <paramref name="server"/>: its rules
    /// and nothing else.
    /// </summary>
    /// <exception cref="PackException">The name is invalid, or the rules do not load.</exception>
    public PolicyDocument RenderPolicy(string server)
    {
        var yaml = new StringBuilder("rules:\n");
        foreach (var line in RenderRules(server))
        {
            yaml.Append(line).Append('\n');
        }

        try
        {
            return PolicyLoader.Parse(yaml.ToString());
        }
        catch (PolicyException ex)
        {
            throw new PackException($"Pack '{Name}' does not load as a policy: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// The entry of <see cref="Recognizes"/> that identifies <paramref name="server"/>,
    /// or null when none does.
    /// </summary>
    /// <remarks>
    /// Matched against the server's command line or URL as written in the
    /// servers file, before variables are expanded, so no secret is ever read
    /// to make the match. An entry starting with <c>http</c> is a URL prefix;
    /// any other entry must equal a whole word of the command line once a
    /// version is stripped, or end it after a <c>/</c> (an image registry or a
    /// directory). Whole words, because a substring test would let
    /// <c>mcp-server-git</c> claim <c>mcp-server-gitlab</c>.
    /// </remarks>
    public string? Recognize(UpstreamServerConfig server)
    {
        ArgumentNullException.ThrowIfNull(server);

        var template = server.DisplayTemplate ?? server.Url?.ToString() ?? string.Empty;
        var words = template.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Select(word => word.Trim('"', '\''))
            .ToList();

        return Recognizes.FirstOrDefault(entry => entry.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? words.Any(word => word.StartsWith(entry, StringComparison.OrdinalIgnoreCase))
            : words.Select(WithoutVersion).Any(word => NamesMatch(word, entry)));
    }

    private static bool NamesMatch(string word, string entry) =>
        word.Equals(entry, StringComparison.OrdinalIgnoreCase) ||
        word.EndsWith("/" + entry, StringComparison.OrdinalIgnoreCase) ||
        word.EndsWith("\\" + entry, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Strips what pins a version from a package, image or binary name:
    /// <c>pkg@1.2</c>, <c>@scope/pkg@1.2</c>, <c>pkg==1.2</c>,
    /// <c>image:tag</c>, <c>image@sha256:...</c> and a Windows <c>.exe</c>.
    /// </summary>
    internal static string WithoutVersion(string word)
    {
        var name = word;

        var pypi = name.IndexOf("==", StringComparison.Ordinal);
        if (pypi > 0)
        {
            name = name[..pypi];
        }

        // Index 0 is a scope (@scope/pkg), not a version.
        var at = name.LastIndexOf('@');
        if (at > 0)
        {
            name = name[..at];
        }

        // A colon after the last slash is an image tag; one before it is a
        // registry port (localhost:5000/image) and stays.
        var colon = name.LastIndexOf(':');
        if (colon > name.LastIndexOf('/') && colon > 1)
        {
            name = name[..colon];
        }

        return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
    }

    private static JsonObject ParseRoot(string text)
    {
        JsonNode? root;
        try
        {
            root = YamlJson.Parse(text);
        }
        catch (YamlJsonException ex)
        {
            throw new PackException(ex.Message, ex);
        }

        if (root is not JsonObject mapping)
        {
            throw new PackException("A pack is a mapping with 'pack:' and 'rules:' keys.");
        }

        var extra = mapping.Select(property => property.Key).Except(["pack", "rules"]).ToList();
        if (extra.Count > 0)
        {
            // Budgets, scanners and approvers are deployment choices with one
            // value per policy; two packs could not both set them.
            throw new PackException(
                $"A pack holds only 'pack:' and 'rules:'; remove {string.Join(", ", extra.Select(key => $"'{key}'"))}.");
        }

        return mapping;
    }

    private static PackHeader ReadHeader(JsonObject root)
    {
        PackHeader? header;
        try
        {
            header = root["pack"]?.Deserialize(GuardrailsJsonContext.Default.PackHeader);
        }
        catch (JsonException ex)
        {
            throw new PackException($"The 'pack:' section is not valid: {ex.Message}", ex);
        }

        if (header is null)
        {
            throw new PackException("A pack needs a 'pack:' section with its name, version and description.");
        }

        if (string.IsNullOrEmpty(header.Name) || !UpstreamServerConfig.IsValidName(header.Name))
        {
            throw new PackException("'pack.name' must be letters, digits and hyphens.");
        }

        if (header.Version is not > 0)
        {
            throw new PackException($"Pack '{header.Name}' needs a positive 'pack.version'.");
        }

        if (string.IsNullOrWhiteSpace(header.Description))
        {
            throw new PackException($"Pack '{header.Name}' needs a one-line 'pack.description'.");
        }

        if (header.Recognizes?.Any(string.IsNullOrWhiteSpace) == true)
        {
            throw new PackException($"Pack '{header.Name}' has an empty entry in 'pack.recognizes'.");
        }

        return header;
    }

    private static void CheckScoped(string name, PolicyDocument policy, string server)
    {
        if (policy.EffectiveRules.Count == 0)
        {
            throw new PackException($"Pack '{name}' has no rules.");
        }

        var unscoped = policy.EffectiveRules
            .Where(rule => rule.EffectiveMatch.Server != server)
            .Select(rule => rule.Name)
            .ToList();
        if (unscoped.Count > 0)
        {
            throw new PackException(
                $"Pack '{name}': every rule needs 'server: \"{Placeholder}\"' so it cannot match " +
                $"another server's tools; missing on {string.Join(", ", unscoped.Select(rule => $"'{rule}'"))}.");
        }

        var duplicates = policy.EffectiveRules
            .GroupBy(rule => rule.Name, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .ToList();
        if (duplicates.Count > 0)
        {
            throw new PackException(
                $"Pack '{name}' has more than one rule named {string.Join(", ", duplicates.Select(rule => $"'{rule}'"))}.");
        }

        if (policy.EffectiveRules.FirstOrDefault(rule => !rule.Name.Contains(server, StringComparison.Ordinal))
            is { } fixedName)
        {
            // Two servers given the same pack would otherwise produce two rules
            // with one name, and the audit log could not say which matched.
            throw new PackException(
                $"Pack '{name}': rule '{fixedName.Name}' needs '{Placeholder}' in its name, " +
                "so the same pack can serve two servers.");
        }
    }
}

/// <summary>The <c>pack:</c> section of a pack file.</summary>
/// <remarks>
/// A wire DTO like the policy records: every property nullable, because the
/// source-generated deserializer does not apply initializers. Unknown keys are
/// refused, because a misspelt <c>recognises:</c> would otherwise just never
/// recognise anything.
/// </remarks>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PackHeader
{
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("version")]
    public int? Version { get; init; }

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("recognizes")]
    public IReadOnlyList<string>? Recognizes { get; init; }
}

/// <summary>A pack that cannot be used, or a pack request that cannot be met.</summary>
public sealed class PackException : Exception
{
    public PackException(string message) : base(message)
    {
    }

    public PackException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
