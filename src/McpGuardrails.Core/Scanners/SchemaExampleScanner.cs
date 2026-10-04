using System.Text;
using System.Text.Json;
using McpGuardrails.Core.Text;

namespace McpGuardrails.Core.Scanners;

/// <summary>
/// An argument detector that fired on a value a tool's input schema suggests.
/// </summary>
/// <param name="Location">
/// Where in the schema, e.g. <c>properties.url.default</c> or <c>examples[0]</c>.
/// </param>
/// <param name="Detector">The detector's name, e.g. <c>ssrf</c>.</param>
public sealed record SchemaExampleHit(string Location, string Detector);

/// <summary>
/// Runs the argument detectors over the values a tool's input schema puts in
/// front of the model: <c>default</c>, <c>const</c>, <c>enum</c>, <c>examples</c>
/// and the OpenAPI-style singular <c>example</c>.
/// </summary>
/// <remarks>
/// A model that fills in arguments copies what the schema suggests. A default of
/// <c>http://169.254.169.254/latest/meta-data/</c> or an example path of
/// <c>~/.aws/credentials</c> is the server asking for that request without ever
/// saying so in prose, which the injection heuristics would catch. Running the
/// same detectors the proxy applies to real calls answers "would this suggestion
/// be flagged if the model followed it?".
///
/// Each suggested value is scanned as if it were the argument it belongs to, so
/// the detectors that look at an argument's name (a path-like name makes a value
/// with spaces a path) see the same name a real call would carry. Linear in the
/// size of the schema: each node is visited once and each value scanned once.
///
/// An <c>enum</c> is the strongest suggestion a schema can make - the model has
/// to pick one of its members - so each member is scanned. Locations are built
/// from keys the server chose and end up in a report printed to a terminal, so
/// each key goes through <see cref="TerminalText.Printable"/> as it is joined.
/// </remarks>
public static class SchemaExampleScanner
{
    // The same depth the argument scanner and the JSON reader stop at.
    private const int _maxDepth = ArgumentScanner.MaxDepth;

    // Locations are built from property names the server chose; long enough to
    // find the spot, short enough that a hostile name cannot fill the report.
    private const int _maxLocationLength = 120;

    private static readonly ArgumentDetectors _all =
        ArgumentDetector.Configurable.Aggregate(ArgumentDetectors.None, (all, name) => all | ArgumentDetector.Parse(name));

    /// <summary>Every detector hit in the suggested values of <paramref name="inputSchema"/>.</summary>
    /// <param name="toolName">The tool's name; decides whether every string is a command.</param>
    /// <param name="inputSchema">The tool's input schema. Undefined or non-object is clean.</param>
    public static IReadOnlyList<SchemaExampleHit> Scan(string toolName, JsonElement inputSchema)
    {
        ArgumentNullException.ThrowIfNull(toolName);

        var hits = new List<SchemaExampleHit>();
        Walk(toolName, inputSchema, location: string.Empty, argument: null, depth: 1, hits);
        return hits;
    }

    private static void Walk(
        string toolName, JsonElement schema, string location, string? argument, int depth, List<SchemaExampleHit> hits)
    {
        if (schema.ValueKind is not JsonValueKind.Object || depth > _maxDepth)
        {
            return;
        }

        foreach (var keyword in schema.EnumerateObject())
        {
            var here = Join(location, keyword.Name);

            switch (keyword.Name)
            {
                case "default" or "const" or "example":
                    Suggest(toolName, keyword.Value, here, argument, hits);
                    break;

                case "examples" or "enum" when keyword.Value.ValueKind is JsonValueKind.Array:
                    var index = 0;
                    foreach (var example in keyword.Value.EnumerateArray())
                    {
                        Suggest(toolName, example, $"{here}[{index++}]", argument, hits);
                    }

                    break;

                case "properties" or "patternProperties" or "$defs" or "definitions" or "dependentSchemas" or "dependencies"
                    when keyword.Value.ValueKind is JsonValueKind.Object:
                    // Under properties, a key is an argument name; under $defs it
                    // names a reusable schema, and under dependentSchemas a schema
                    // that applies to the whole object, so the argument name in
                    // scope stays the one we arrived with. A draft-07 dependencies
                    // entry may be an array of names rather than a schema, which
                    // Walk ignores as not an object.
                    var named = keyword.Name is "properties" or "patternProperties";
                    foreach (var child in keyword.Value.EnumerateObject())
                    {
                        Walk(toolName, child.Value, Join(here, child.Name), named ? child.Name : argument, depth + 1, hits);
                    }

                    break;

                case "anyOf" or "oneOf" or "allOf" or "prefixItems" or "items" or "additionalItems"
                    when keyword.Value.ValueKind is JsonValueKind.Array:
                    // items and additionalItems as arrays are the draft-04/07
                    // tuple form: one schema per position.
                    var position = 0;
                    foreach (var branch in keyword.Value.EnumerateArray())
                    {
                        Walk(toolName, branch, $"{here}[{position++}]", argument, depth + 1, hits);
                    }

                    break;

                case "items" or "additionalItems" or "additionalProperties" or "unevaluatedItems" or "unevaluatedProperties"
                    or "propertyNames" or "not" or "if" or "then" or "else" or "contains":
                    Walk(toolName, keyword.Value, here, argument, depth + 1, hits);
                    break;
            }
        }
    }

    /// <summary>Scans one suggested value as the argument it would become.</summary>
    /// <remarks>
    /// At the root, a suggested value is a whole set of arguments, so its
    /// properties are scanned as arguments. Below the root it is the value of the
    /// argument in scope - or, under <c>$defs</c> where no argument name is known,
    /// of an argument with no name, which only loses the name-based path hints.
    /// </remarks>
    private static void Suggest(
        string toolName, JsonElement value, string location, string? argument, List<SchemaExampleHit> hits)
    {
        IEnumerable<KeyValuePair<string, JsonElement>> arguments = argument is null && value.ValueKind is JsonValueKind.Object
            ? value.EnumerateObject().Select(property => new KeyValuePair<string, JsonElement>(property.Name, property.Value))
            : [new KeyValuePair<string, JsonElement>(argument ?? string.Empty, value)];

        foreach (var hit in ArgumentScanner.Scan(toolName, arguments, _all).Hits)
        {
            hits.Add(new SchemaExampleHit(location, hit.Detector));
        }
    }

    private static string Join(string location, string segment)
    {
        var builder = new StringBuilder(location.Length + segment.Length + 1);
        if (location.Length > 0)
        {
            builder.Append(location).Append('.');
        }

        builder.Append(TerminalText.Printable(segment));

        return builder.Length <= _maxLocationLength
            ? builder.ToString()
            : string.Concat(builder.ToString(0, _maxLocationLength - 3), "...");
    }
}
