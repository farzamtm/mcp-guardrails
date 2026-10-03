using ModelContextProtocol.Protocol;

namespace McpGuardrails.Core.Upstream;

/// <summary>
/// Translates between the tool names the client sees ("fs__read_file") and the
/// names the downstream server knows ("read_file").
/// </summary>
/// <remarks>
/// Two different servers may both expose a tool called "read_file". The client
/// sees one flat list, so the names must be made unique before merging.
///
/// This class is pure string manipulation with no I/O and no dependencies, which
/// makes it the easiest thing in the codebase to unit-test exhaustively. That is
/// not an accident - push logic into pure functions and the tests get trivial.
/// </remarks>
public static class ToolNamespacer
{
    /// <summary>
    /// Separator between server name and tool name. Double underscore survives
    /// the MCP tool-name charset (letters, digits, underscore, hyphen), unlike a
    /// dot, which some clients reject.
    /// </summary>
    public const string Separator = "__";

    /// <summary>Combines a server name and a downstream tool name.</summary>
    public static string Qualify(string serverName, string toolName)
        => $"{serverName}{Separator}{toolName}";

    /// <summary>
    /// Copies a downstream tool descriptor, replacing only its name with the
    /// namespaced one the client should see.
    /// </summary>
    /// <remarks>
    /// Do NOT reach for McpClientTool.WithName here. That changes the name on the
    /// client-side wrapper only; the underlying ProtocolTool it exposes keeps the
    /// original name. Using it makes tools/list advertise "write_file" while
    /// tools/call only accepts "fs__write_file", which breaks every client.
    ///
    /// Tool is a plain mutable DTO rather than a record, so there is no `with`
    /// expression available and the copy has to be spelled out. Every field is
    /// carried over deliberately - especially Annotations, which is what the
    /// policy engine matches destructiveHint/readOnlyHint on.
    /// </remarks>
    public static Tool Qualify(string serverName, Tool tool)
    {
        ArgumentNullException.ThrowIfNull(tool);

        return new Tool
        {
            Name = Qualify(serverName, tool.Name),
            Title = tool.Title,
            Description = tool.Description,
            InputSchema = tool.InputSchema,
            OutputSchema = tool.OutputSchema,
            Annotations = tool.Annotations,
            Icons = tool.Icons,
            Meta = tool.Meta,
        };
    }

    /// <summary>
    /// Splits a qualified name back into its parts.
    /// </summary>
    /// <remarks>
    /// Returns bool rather than throwing, because an unknown tool name is an
    /// expected condition - a client can call anything it likes - not a bug.
    /// Exceptions are for the unexpected.
    ///
    /// `out` parameters let a method return several values. The caller writes
    /// `if (TrySplit(x, out var s, out var t))` and `s`/`t` are in scope after.
    /// The Try-prefix + bool + out pattern is a strong .NET convention; follow it
    /// and reviewers instantly know the contract.
    ///
    /// Splitting on the FIRST separator matters: server names cannot contain "__"
    /// (enforced in UpstreamServerConfig.Validate) but tool names can, so
    /// "fs__read__file" must resolve to server "fs", tool "read__file".
    /// </remarks>
    public static bool TrySplit(
        string qualifiedName,
        out string serverName,
        out string toolName)
    {
        var index = qualifiedName.IndexOf(Separator, StringComparison.Ordinal);

        // Reject a missing separator, and also a leading one ("__foo"), which
        // would yield an empty server name.
        if (index <= 0)
        {
            serverName = string.Empty;
            toolName = string.Empty;
            return false;
        }

        serverName = qualifiedName[..index];
        toolName = qualifiedName[(index + Separator.Length)..];

        // A trailing separator ("fs__") leaves an empty tool name.
        if (toolName.Length == 0)
        {
            serverName = string.Empty;
            return false;
        }

        return true;
    }
}
