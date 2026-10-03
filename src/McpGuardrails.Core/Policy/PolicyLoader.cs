using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using McpGuardrails.Core.Serialization;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace McpGuardrails.Core.Policy;

/// <summary>
/// Reads a YAML policy file into a <see cref="PolicyDocument"/>.
/// </summary>
/// <remarks>
/// The two-stage conversion (YAML to JsonNode to typed object) is deliberate and
/// is the mitigation the spec calls for.
///
/// YamlDotNet's convenient path is its Deserializer, which binds straight onto
/// your classes using reflection. Native AOT trims the metadata that depends on,
/// so it breaks - silently, by producing objects with every property null, which
/// for a security policy would mean "no rules" and a proxy that allows
/// everything.
///
/// So we use YamlDotNet only as a PARSER, via its representation model, which is
/// pure data with no reflection. Then System.Text.Json's source-generated
/// deserializer does the binding, and that is statically analysable and
/// AOT-safe.
/// </remarks>
public static class PolicyLoader
{
    /// <summary>
    /// Loads the policy at <paramref name="path"/>, or an empty policy if there
    /// is no file there.
    /// </summary>
    /// <remarks>
    /// A missing file is normal - it is the passthrough default that makes the
    /// proxy adoptable. A malformed file throws: failing open because the policy
    /// would not parse is the worst possible behaviour for a security tool.
    /// </remarks>
    public static PolicyDocument LoadFromFileOrEmpty(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        // A directory is not "no policy". File.Exists returns false for one, so
        // without this check a misconfigured path would fall through to the empty
        // policy and allow everything - a silent fail-open, which is the single
        // worst failure mode available to this component.
        if (Directory.Exists(path))
        {
            throw new PolicyException(
                $"Could not read the policy file: '{path}' is a directory, not a file.");
        }

        // A genuinely absent file IS "no policy": passthrough with audit logging.
        if (!File.Exists(path))
        {
            return PolicyDocument.Empty;
        }

        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (IOException ex)
        {
            throw new PolicyException($"Could not read the policy file: {ex.Message}", ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new PolicyException($"Could not read the policy file: {ex.Message}", ex);
        }

        return Parse(text);
    }

    /// <summary>Parses policy YAML from a string.</summary>
    public static PolicyDocument Parse(string yaml)
    {
        ArgumentNullException.ThrowIfNull(yaml);

        // An empty or comments-only document is a valid "no rules" policy.
        if (string.IsNullOrWhiteSpace(yaml))
        {
            return PolicyDocument.Empty;
        }

        var stream = new YamlStream();
        try
        {
            stream.Load(new StringReader(yaml));
        }
        catch (YamlException ex)
        {
            // YamlException carries line/column; surfacing them turns "invalid
            // policy" into something the user can actually go and fix.
            throw new PolicyException(
                $"YAML syntax error at line {ex.Start.Line}, column {ex.Start.Column}: {ex.Message}",
                ex);
        }

        if (stream.Documents.Count == 0)
        {
            return PolicyDocument.Empty;
        }

        var json = ToJsonNode(stream.Documents[0].RootNode);

        PolicyDocument? document;
        try
        {
            document = json.Deserialize(GuardrailsJsonContext.Default.PolicyDocument);
        }
        catch (JsonException ex)
        {
            throw new PolicyException($"Policy file is not valid: {ex.Message}", ex);
        }

        document ??= PolicyDocument.Empty;

        // Fail at load time rather than on the first tool call, so a typo is
        // caught when the proxy starts instead of hours later mid-session.
        foreach (var rule in document.EffectiveRules)
        {
            rule.Validate();
        }

        document.EffectiveBudgets.Validate();
        document.EffectiveApprovers.Validate(document.EffectiveRules);
        document.EffectiveScanners.Validate();

        return document;
    }

    /// <summary>Converts YamlDotNet's representation model into a JsonNode tree.</summary>
    /// <remarks>
    /// Excluded from coverage, deliberately and narrowly.
    ///
    /// This is pure dispatch: the three real conversions it delegates to are
    /// thoroughly covered through Parse. Only the final arm is uncoverable -
    /// YamlAliasNode is internal to YamlDotNet, so no test can construct a node
    /// outside the three handled types. The arm still has to exist, both for
    /// switch exhaustiveness and so a future node type produces a clear
    /// PolicyException rather than a SwitchExpressionException.
    ///
    /// Excluding six lines of dispatch whose behaviour is covered elsewhere is
    /// honest; lowering the global threshold to accommodate them would not be,
    /// because it would silently license coverage loss everywhere else.
    /// </remarks>
    [ExcludeFromCodeCoverage(Justification =
        "Dispatch only; the unsupported-node arm cannot be reached because " +
        "YamlAliasNode is internal to YamlDotNet. Delegates are covered via Parse.")]
    private static JsonNode? ToJsonNode(YamlNode node) => node switch
    {
        YamlMappingNode mapping => ToJsonObject(mapping),
        YamlSequenceNode sequence => ToJsonArray(sequence),
        YamlScalarNode scalar => ToJsonValue(scalar),
        _ => throw new PolicyException($"Unsupported YAML node type: {node.GetType().Name}"),
    };

    private static JsonObject ToJsonObject(YamlMappingNode mapping)
    {
        var result = new JsonObject();

        foreach (var (key, value) in mapping.Children)
        {
            if (key is not YamlScalarNode { Value: { } name })
            {
                throw new PolicyException("Policy keys must be plain strings.");
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
