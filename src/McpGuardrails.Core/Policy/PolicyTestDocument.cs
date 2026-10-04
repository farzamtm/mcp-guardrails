using System.Text.Json;
using System.Text.Json.Serialization;

namespace McpGuardrails.Core.Policy;

/// <summary>
/// A <c>policy test</c> file: a policy, the tools it is tested against, and
/// calls with the decision each should get.
/// </summary>
/// <remarks>
/// <code>
/// policy: github.yaml          # relative to this file
/// server: gh                   # fills a pack's placeholder; ignored for a plain policy
/// tools:                       # what the servers advertise, with their hints
///   gh__get_file_contents: { readOnlyHint: true }
///   gh__create_issue: {}
/// cases:
///   - call: gh__create_issue
///     args: { title: hi }
///     expect: require_approval
///     rule: gh-approve-writes   # optional: which rule should decide it
/// </code>
///
/// Unknown keys are refused at every level. In a test file a misspelt
/// <c>expected:</c> would otherwise leave a case asserting nothing, and a test
/// that cannot fail is worse than no test because it looks like coverage.
/// </remarks>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PolicyTestDocument
{
    /// <summary>The policy or pack under test, relative to the test file.</summary>
    [JsonPropertyName("policy")]
    public string? Policy { get; init; }

    /// <summary>The server name a pack is rendered with.</summary>
    [JsonPropertyName("server")]
    public string? Server { get; init; }

    /// <summary>Advertised tools by qualified name, each with its hints.</summary>
    [JsonPropertyName("tools")]
    public IReadOnlyDictionary<string, PolicyTestTool>? Tools { get; init; }

    /// <summary>The calls, in order.</summary>
    [JsonPropertyName("cases")]
    public IReadOnlyList<PolicyTestCase>? Cases { get; init; }
}

/// <summary>The behaviour hints one test tool advertises.</summary>
/// <remarks>
/// Raw hints, as a server would publish them: an omitted hint gets the MCP
/// default when the policy matches on it, exactly as in the proxy.
/// </remarks>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PolicyTestTool
{
    [JsonPropertyName("readOnlyHint")]
    public bool? ReadOnlyHint { get; init; }

    [JsonPropertyName("destructiveHint")]
    public bool? DestructiveHint { get; init; }

    [JsonPropertyName("idempotentHint")]
    public bool? IdempotentHint { get; init; }

    [JsonPropertyName("openWorldHint")]
    public bool? OpenWorldHint { get; init; }
}

/// <summary>One call and the decision it should get.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PolicyTestCase
{
    /// <summary>Optional label printed with a failure.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    /// <summary>The qualified tool name, as the client calls it.</summary>
    [JsonPropertyName("call")]
    public string? Call { get; init; }

    /// <summary>The call's arguments.</summary>
    [JsonPropertyName("args")]
    public IReadOnlyDictionary<string, JsonElement>? Arguments { get; init; }

    /// <summary>The expected verdict.</summary>
    [JsonPropertyName("expect")]
    public Verdict? Expect { get; init; }

    /// <summary>The rule expected to decide, when the case cares which.</summary>
    [JsonPropertyName("rule")]
    public string? Rule { get; init; }

    /// <summary>
    /// True to call a tool no server advertises, which the proxy still runs
    /// policy for.
    /// </summary>
    /// <remarks>
    /// Must be said out loud: otherwise a typo in <c>call:</c> would quietly
    /// turn a case into a call to an unknown tool and test something else.
    /// </remarks>
    [JsonPropertyName("unknown")]
    public bool? Unknown { get; init; }
}
