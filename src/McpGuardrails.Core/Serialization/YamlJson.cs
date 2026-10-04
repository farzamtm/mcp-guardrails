using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.Json.Nodes;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace McpGuardrails.Core.Serialization;

/// <summary>
/// Parses YAML (and therefore JSON, which YAML 1.2 contains) into a
/// <see cref="JsonNode"/> tree.
/// </summary>
/// <remarks>
/// The first half of a two-stage load, shared by the policy file and the servers
/// file: YamlDotNet is used only as a PARSER, via its representation model, which
/// is pure data with no reflection, and System.Text.Json's source-generated
/// deserializer then binds the tree onto typed records.
///
/// YamlDotNet's convenient path is its Deserializer, which binds straight onto
/// classes using reflection. Native AOT trims the metadata that depends on, so it
/// breaks - silently, by producing objects with every property null, which for a
/// security policy would mean "no rules" and a proxy that allows everything, and
/// for a servers file would mean a server with no command.
/// </remarks>
internal static class YamlJson
{
    /// <summary>
    /// Parses <paramref name="text"/>, returning null for an empty document.
    /// </summary>
    /// <exception cref="YamlJsonException">The text is not well-formed YAML.</exception>
    internal static JsonNode? Parse(string text)
    {
        var stream = new YamlStream();
        try
        {
            stream.Load(new StringReader(text));
        }
        catch (YamlException ex)
        {
            // YamlException carries line/column; surfacing them turns "invalid
            // file" into something the user can actually go and fix.
            throw new YamlJsonException(
                $"YAML syntax error at line {ex.Start.Line}, column {ex.Start.Column}: {ex.Message}",
                ex);
        }

        return stream.Documents.Count == 0 ? null : ToJsonNode(stream.Documents[0].RootNode);
    }

    /// <summary>Converts YamlDotNet's representation model into a JsonNode tree.</summary>
    /// <remarks>
    /// Excluded from coverage, deliberately and narrowly.
    ///
    /// This is pure dispatch: the three real conversions it delegates to are
    /// thoroughly covered through the loaders. Only the final arm is uncoverable -
    /// YamlAliasNode is internal to YamlDotNet, so no test can construct a node
    /// outside the three handled types. The arm still has to exist, both for
    /// switch exhaustiveness and so a future node type produces a clear error
    /// rather than a SwitchExpressionException.
    ///
    /// Excluding six lines of dispatch whose behaviour is covered elsewhere is
    /// honest; lowering the global threshold to accommodate them would not be,
    /// because it would silently license coverage loss everywhere else.
    /// </remarks>
    [ExcludeFromCodeCoverage(Justification =
        "Dispatch only; the unsupported-node arm cannot be reached because " +
        "YamlAliasNode is internal to YamlDotNet. Delegates are covered via the loaders.")]
    private static JsonNode? ToJsonNode(YamlNode node) => node switch
    {
        YamlMappingNode mapping => ToJsonObject(mapping),
        YamlSequenceNode sequence => ToJsonArray(sequence),
        YamlScalarNode scalar => ToJsonValue(scalar),
        _ => throw new YamlJsonException($"Unsupported YAML node type: {node.GetType().Name}"),
    };

    private static JsonObject ToJsonObject(YamlMappingNode mapping)
    {
        var result = new JsonObject();

        foreach (var (key, value) in mapping.Children)
        {
            if (key is not YamlScalarNode { Value: { } name })
            {
                throw new YamlJsonException("Mapping keys must be plain strings.");
            }

            // Later duplicate keys win, matching YAML merge behaviour, rather
            // than throwing on a file most parsers would accept.
            result[name] = ToJsonNode(value);
        }

        return result;
    }

    private static JsonArray ToJsonArray(YamlSequenceNode sequence)
    {
        var result = new JsonArray();

        foreach (var child in sequence.Children)
        {
            result.Add(ToJsonNode(child));
        }

        return result;
    }

    /// <summary>
    /// Converts a YAML scalar, inferring bool and number for unquoted values.
    /// </summary>
    /// <remarks>
    /// Style matters here. In YAML, <c>true</c> is a boolean but <c>"true"</c> is
    /// a string, and the parser preserves that distinction in
    /// <see cref="YamlScalarNode.Style"/>. Honouring it means a quoted value is
    /// never silently retyped, which matters because annotation matching and
    /// argument predicates compare against real booleans and numbers.
    /// </remarks>
    internal static JsonNode? ToJsonValue(YamlScalarNode scalar)
    {
        var value = scalar.Value;

        if (value is null)
        {
            return null;
        }

        // Quoted means the author explicitly asked for a string.
        if (scalar.Style is ScalarStyle.SingleQuoted or ScalarStyle.DoubleQuoted)
        {
            return JsonValue.Create(value);
        }

        if (value.Length == 0 || value is "~" or "null" or "Null" or "NULL")
        {
            return null;
        }

        if (value is "true" or "True" or "TRUE")
        {
            return JsonValue.Create(true);
        }

        if (value is "false" or "False" or "FALSE")
        {
            return JsonValue.Create(false);
        }

        if (long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var integer))
        {
            return JsonValue.Create(integer);
        }

        if (double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var number))
        {
            return JsonValue.Create(number);
        }

        return JsonValue.Create(value);
    }
}

/// <summary>A file that is not well-formed YAML, or uses YAML JSON cannot represent.</summary>
/// <remarks>
/// Each loader catches this and rethrows its own exception type, so the CLI keeps
/// printing "invalid policy file" or "invalid servers file" rather than a parser
/// detail the user never asked about.
/// </remarks>
internal sealed class YamlJsonException : Exception
{
    public YamlJsonException(string message) : base(message)
    {
    }

    public YamlJsonException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
