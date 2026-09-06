using System.ComponentModel;
using ModelContextProtocol.Server;

namespace McpGuardrails.Core.Tools;

/// <summary>
/// A throwaway tool used to prove the stdio plumbing works end to end.
/// Delete this once the proxy forwards real downstream tools (step 3).
/// </summary>
/// <remarks>
/// C# notes for someone arriving from Java/TypeScript:
///
/// - [McpServerToolType] marks this class as a container of tools. Attributes are
///   metadata attached to declarations, like Java annotations or TS decorators.
///   The SDK scans for them and builds the JSON-RPC tool schema from the method
///   signature, so you never hand-write a JSON schema.
///
/// - The class is NOT `static`, even though every member is. C# forbids static
///   types as generic type arguments (CS0718), and `WithTools<T>()` needs a real
///   type argument. `sealed` says "nothing may inherit from this", which is the
///   sane default for a leaf class in C#.
///
/// - [Description] on the method and on each parameter is not decoration: those
///   strings are shipped to the model as the tool description. They are prompt
///   text. Write them for an LLM reader, not for a human maintainer.
/// </remarks>
[McpServerToolType]
public sealed class EchoTool
{
    [McpServerTool(Name = "echo")]
    [Description("Echoes the supplied message back to the caller. Used to verify connectivity.")]
    public static string Echo(
        [Description("The message to echo back.")] string message)
        // Expression-bodied member: `=> expr` is shorthand for `{ return expr; }`.
        // $"..." is an interpolated string, the same idea as a JS template literal.
        => $"echo: {message}";
}
