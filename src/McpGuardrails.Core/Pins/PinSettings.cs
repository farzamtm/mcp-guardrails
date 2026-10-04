using System.Text.Json.Serialization;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Pins;

/// <summary>What to do with a tool whose definition differs from its pin.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<PinMode>))]
public enum PinMode
{
    /// <summary>
    /// Advertise a changed tool with a warning in front of its description, and
    /// log and audit the change.
    /// </summary>
    /// <remarks>
    /// The zero value and the default, for the reason the metadata scanner
    /// defaults to annotating: it cannot break a workflow. Under <c>block</c>
    /// every routine server upgrade would make its changed tools disappear until
    /// someone runs <c>pins accept</c>, and a guardrail that breaks things on
    /// upgrade day is the one people switch off.
    /// </remarks>
    [JsonStringEnumMemberName("warn")]
    Warn,

    /// <summary>Withhold a changed tool from <c>tools/list</c> and refuse calls to it.</summary>
    [JsonStringEnumMemberName("block")]
    Block,

    /// <summary>Do not read, compare or write pins at all.</summary>
    [JsonStringEnumMemberName("off")]
    Off,
}

/// <summary>What to do with a tool that was not there when its server was pinned.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<NewToolAction>))]
public enum NewToolAction
{
    /// <summary>Advertise it with a warning saying it is new.</summary>
    [JsonStringEnumMemberName("warn")]
    Warn,

    /// <summary>Withhold it until someone accepts it.</summary>
    [JsonStringEnumMemberName("block")]
    Block,

    /// <summary>Advertise it unchanged. Still logged and audited.</summary>
    [JsonStringEnumMemberName("allow")]
    Allow,
}

/// <summary>
/// The <c>scanners.pins</c> section: remembering tool definitions across restarts.
/// </summary>
/// <remarks>
/// Under <c>scanners:</c> because, like metadata scanning, it decides what the
/// model is shown of a server's tool list rather than identifying a call.
/// </remarks>
public sealed record PinSettings
{
    /// <summary>The settings used when the policy file says nothing.</summary>
    public static PinSettings Default { get; } = new();

    /// <summary>Pinning off entirely.</summary>
    public static PinSettings Disabled { get; } = new() { Mode = PinMode.Off };

    /// <summary>What to do with a changed tool: <c>warn</c>, <c>block</c> or <c>off</c>.</summary>
    [JsonPropertyName("mode")]
    public PinMode? Mode { get; init; }

    /// <inheritdoc cref="Mode" />
    [JsonIgnore]
    public PinMode EffectiveMode => Mode ?? PinMode.Warn;

    /// <summary>What to do with a tool added since the pin: <c>warn</c>, <c>block</c> or <c>allow</c>.</summary>
    [JsonPropertyName("on_new_tool")]
    public NewToolAction? OnNewTool { get; init; }

    /// <inheritdoc cref="OnNewTool" />
    [JsonIgnore]
    public NewToolAction EffectiveOnNewTool => OnNewTool ?? NewToolAction.Warn;

    /// <summary>
    /// Where the pins file lives. <c>~/</c> means the home directory, and a
    /// relative path is resolved against the policy file's directory.
    /// </summary>
    /// <remarks>
    /// The <see cref="PinsFile.PathVariable"/> environment variable wins over this,
    /// as it does for the other files: the policy says what to enforce, the
    /// deployment says where state lives.
    /// </remarks>
    [JsonPropertyName("file")]
    public string? File { get; init; }

    /// <summary>True when pins should not be consulted.</summary>
    [JsonIgnore]
    public bool IsOff => EffectiveMode is PinMode.Off;

    internal void Validate()
    {
        if (!Enum.IsDefined(EffectiveMode))
        {
            throw new PolicyException("'scanners.pins.mode' is not a known mode. Use warn, block or off.");
        }

        if (!Enum.IsDefined(EffectiveOnNewTool))
        {
            throw new PolicyException(
                "'scanners.pins.on_new_tool' is not a known action. Use warn, block or allow.");
        }

        if (File is { } file && string.IsNullOrWhiteSpace(file))
        {
            throw new PolicyException("'scanners.pins.file' is empty. Remove it to use the default location.");
        }
    }
}
