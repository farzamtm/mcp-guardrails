using System.Text.Json;
using System.Text.Json.Serialization;

namespace McpGuardrails.Core.Upstream;

/// <summary>
/// The <c>defaults:</c> section of a servers file: settings every server
/// inherits unless it sets its own.
/// </summary>
/// <remarks>
/// A wire DTO, bound by the source-generated deserializer from the YAML-derived
/// JSON tree, like the policy records. Every property is nullable because
/// property initializers are not applied by that deserializer, so "absent" has
/// to be modelled rather than defaulted.
/// </remarks>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ServerDefaultsDocument
{
    /// <summary>How long a stdio child gets to exit on shutdown, e.g. <c>5s</c>.</summary>
    [JsonPropertyName("shutdown_timeout")]
    public JsonElement? ShutdownTimeout { get; init; }

    /// <summary>Variable names (or globs) passed to every isolated child, on top of the built-in list.</summary>
    [JsonPropertyName("env_passthrough")]
    public IReadOnlyList<string>? EnvPassthrough { get; init; }

    /// <summary>Whether stdio children start with only an allowlisted environment.</summary>
    [JsonPropertyName("env_isolation")]
    public bool? EnvIsolation { get; init; }
}

/// <summary>One entry under <c>servers:</c> (or <c>mcpServers:</c>).</summary>
/// <remarks>
/// A flat record holding every field of every transport, rather than a
/// polymorphic hierarchy keyed on <c>type</c>: <c>[JsonPolymorphic]</c> needs the
/// discriminator first in the object, which no hand-written config guarantees,
/// and a flat record lets the loader report "a stdio server cannot have a url"
/// instead of a deserializer's complaint about an unknown property.
///
/// Unknown keys are rejected before this is bound (see
/// <see cref="ServersLoader"/>), so every misspelling is reported at once; the
/// Disallow attribute is the backstop should the two lists ever drift.
/// </remarks>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ServerEntryDocument
{
    /// <summary><c>stdio</c>, <c>http</c> (alias <c>streamable-http</c>) or <c>sse</c>.</summary>
    [JsonPropertyName("type")]
    public string? Type { get; init; }

    [JsonPropertyName("command")]
    public string? Command { get; init; }

    [JsonPropertyName("args")]
    public IReadOnlyList<string>? Args { get; init; }

    /// <summary>Values may be strings, numbers, booleans or null, as VS Code allows.</summary>
    [JsonPropertyName("env")]
    public IReadOnlyDictionary<string, JsonElement>? Env { get; init; }

    [JsonPropertyName("env_file")]
    public string? EnvFile { get; init; }

    /// <summary>Cursor's and VS Code's spelling of <see cref="EnvFile"/>.</summary>
    [JsonPropertyName("envFile")]
    public string? EnvFileCamel { get; init; }

    [JsonPropertyName("cwd")]
    public string? Cwd { get; init; }

    [JsonPropertyName("url")]
    public string? Url { get; init; }

    [JsonPropertyName("headers")]
    public IReadOnlyDictionary<string, string>? Headers { get; init; }

    [JsonPropertyName("disabled")]
    public bool? Disabled { get; init; }

    [JsonPropertyName("optional")]
    public bool? Optional { get; init; }

    [JsonPropertyName("shutdown_timeout")]
    public JsonElement? ShutdownTimeout { get; init; }

    [JsonPropertyName("env_passthrough")]
    public IReadOnlyList<string>? EnvPassthrough { get; init; }

    [JsonPropertyName("env_isolation")]
    public bool? EnvIsolation { get; init; }

    /// <summary>
    /// Reserved for options only the proxy understands. Accepted and unused, so a
    /// file written for a later version still loads here.
    /// </summary>
    [JsonPropertyName("x-guardrails")]
    public JsonElement? Guardrails { get; init; }
}
