using System.Reflection;

namespace McpGuardrails.Core.Packs;

/// <summary>The packs shipped inside the binary.</summary>
/// <remarks>
/// Embedded as resources (see the Core project file) rather than read from a
/// folder next to the executable: a Native AOT binary is one file, copied
/// wherever the user likes, and a manifest resource is the one kind of
/// shipped content that cannot get separated from it. Reading one involves no
/// reflection over types, so trimming leaves it alone.
/// </remarks>
public sealed class PackCatalog
{
    private const string _resourcePrefix = "packs/";

    private PackCatalog(IReadOnlyList<PolicyPack> packs) => All = packs;

    /// <summary>Every pack, ordered by name.</summary>
    public IReadOnlyList<PolicyPack> All { get; }

    /// <summary>The packs compiled into this build.</summary>
    /// <remarks>
    /// Lazy so commands that never touch packs - serving, above all - do not
    /// parse nine YAML files at startup.
    /// </remarks>
    public static PackCatalog BuiltIn => _builtIn.Value;

    private static readonly Lazy<PackCatalog> _builtIn = new(() =>
    {
        var assembly = typeof(PackCatalog).Assembly;
        return FromTexts(assembly.GetManifestResourceNames()
            .Where(name => name.StartsWith(_resourcePrefix, StringComparison.Ordinal))
            .Select(name => ReadResource(assembly, name)));
    });

    /// <summary>A catalog of the given pack texts.</summary>
    /// <exception cref="PackException">A pack is malformed, or two share a name.</exception>
    public static PackCatalog FromTexts(IEnumerable<string> texts)
    {
        ArgumentNullException.ThrowIfNull(texts);

        var packs = texts.Select(PolicyPack.Parse).OrderBy(pack => pack.Name, StringComparer.Ordinal).ToList();

        if (packs.GroupBy(pack => pack.Name, StringComparer.Ordinal).FirstOrDefault(group => group.Count() > 1)
            is { } duplicate)
        {
            throw new PackException($"Two packs are named '{duplicate.Key}'.");
        }

        return new PackCatalog(packs);
    }

    /// <summary>The pack called <paramref name="name"/>, or null.</summary>
    public PolicyPack? Find(string name) =>
        All.FirstOrDefault(pack => pack.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    private static string ReadResource(Assembly assembly, string name)
    {
        // Never null: the name came from this assembly's own resource list.
        using var stream = assembly.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
