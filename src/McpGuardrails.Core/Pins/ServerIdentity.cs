using System.Text.Json;
using McpGuardrails.Core.Serialization;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Pins;

/// <summary>
/// Which program a server name stands for, as a hash.
/// </summary>
/// <remarks>
/// Pins are keyed by name, but a name is only a label in the servers file.
/// Pointing <c>github</c> at a different package version, a different image or a
/// different URL is the moment the tools are most likely to change, and the
/// operator should be told that is what happened rather than see a list of
/// individually changed tools.
///
/// For stdio, the expanded command and arguments; environment values are left
/// out so a secret passed through <c>env</c> never feeds a hash that may be
/// committed to a repository. For remote servers, the normalized URL.
/// </remarks>
public static class ServerIdentity
{
    /// <summary>The identity hash of <paramref name="config"/>.</summary>
    public static string Fingerprint(UpstreamServerConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        var buffer = new System.Buffers.ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("transport", config.Transport.ToWireName());

            if (config.Transport is UpstreamTransport.Stdio)
            {
                writer.WriteString("command", config.Command);
                writer.WriteStartArray("args");
                foreach (var argument in config.Arguments)
                {
                    writer.WriteStringValue(argument);
                }

                writer.WriteEndArray();
            }
            else
            {
                // AbsoluteUri lowercases the scheme and host and drops a default
                // port, so https://Example.com:443/mcp and https://example.com/mcp
                // are one server.
                writer.WriteString("url", config.Url!.AbsoluteUri);
            }

            writer.WriteEndObject();
        }

        using var document = JsonDocument.Parse(buffer.WrittenMemory);
        return CanonicalJson.Hash(document.RootElement);
    }

    /// <summary>What the pins file shows a person: the unexpanded template.</summary>
    /// <remarks>
    /// The servers file's own text, with <c>${VAR}</c> unexpanded and anything
    /// secret-shaped already masked by the loader. A server defined in code has
    /// no template; its command line is the proxy's own and holds no secret.
    /// </remarks>
    public static string Hint(UpstreamServerConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        return config.DisplayTemplate
               ?? (config.Transport is UpstreamTransport.Stdio
                   ? string.Join(' ', [config.Command, .. config.Arguments])
                   : config.Url!.AbsoluteUri);
    }
}
