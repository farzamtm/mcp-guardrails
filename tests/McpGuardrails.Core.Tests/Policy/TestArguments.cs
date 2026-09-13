using System.Text.Json;

namespace McpGuardrails.Core.Tests.Policy;

/// <summary>
/// Builds a tool call's arguments from JSON, the way the SDK hands them over.
/// </summary>
/// <remarks>
/// Writing the arguments as literal JSON rather than assembling JsonElements by
/// hand keeps the tests readable and, more usefully, keeps them honest about the
/// shapes that actually arrive over the wire.
/// </remarks>
internal static class TestArguments
{
    internal static IReadOnlyDictionary<string, JsonElement> From(string json)
    {
        // JsonDocument rather than JsonSerializer.Deserialize: the solution builds
        // with IsAotCompatible, so the reflection-based overload is a build error
        // here exactly as it would be in Core. Clone() because the elements have
        // to outlive the document.
        using var document = JsonDocument.Parse(json);

        return document.RootElement.EnumerateObject()
            .ToDictionary(property => property.Name, property => property.Value.Clone(), StringComparer.Ordinal);
    }
}
