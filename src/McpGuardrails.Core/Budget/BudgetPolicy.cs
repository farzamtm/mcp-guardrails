using System.Text.Json.Serialization;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Budget;

/// <summary>
/// The <c>budgets:</c> section of a policy file.
/// </summary>
/// <remarks>
/// A policy answers "may this call happen?". A budget answers "how many times?".
/// The difference matters because the dangerous agent is rarely the one making a
/// call it should not make - it is the one making a permitted call four thousand
/// times in a loop.
/// </remarks>
public sealed record BudgetPolicy
{
    /// <summary>Caps for the lifetime of this proxy process.</summary>
    [JsonPropertyName("session")]
    public BudgetLimits? Session { get; init; }

    /// <summary>Caps per UTC calendar day, across every session and restart.</summary>
    /// <remarks>
    /// Enforced by <see cref="SqliteBudgetStore"/>, because a day outlives the
    /// proxy process: a daily cap kept in memory would reset whenever the client
    /// reconnected, which is a limit an agent defeats by being restarted.
    /// </remarks>
    [JsonPropertyName("daily")]
    public BudgetLimits? Daily { get; init; }

    /// <summary>No budgets configured: every call passes the gate.</summary>
    public static BudgetPolicy None { get; } = new();

    /// <summary>True when nothing is capped.</summary>
    [JsonIgnore]
    public bool IsEmpty => Session is null && Daily is null;

    /// <summary>Validates the section, throwing with a message naming the problem.</summary>
    public void Validate()
    {
        Session?.Validate(BudgetGate.SessionScope);
        Daily?.Validate(BudgetGate.DailyScope);
    }
}

/// <summary>
/// The caps for one budget scope.
/// </summary>
/// <remarks>
/// Two dimensions, because they answer different questions. <c>max_calls</c>
/// bounds chattiness and needs no cost model to be useful. <c>max_cost</c> bounds
/// damage, using the per-rule <c>cost:</c> weights, so one expensive export can
/// count for more than fifty reads.
/// </remarks>
public sealed record BudgetLimits
{
    /// <summary>Maximum number of tool calls allowed through, or null for no cap.</summary>
    [JsonPropertyName("max_calls")]
    public long? MaxCalls { get; init; }

    /// <summary>Maximum total cost allowed through, or null for no cap.</summary>
    [JsonPropertyName("max_cost")]
    public long? MaxCost { get; init; }

    internal void Validate(string scope)
    {
        if (MaxCalls is null && MaxCost is null)
        {
            throw new PolicyException(
                $"'budgets.{scope}' sets no limits. Give it 'max_calls', 'max_cost' " +
                "or both, or remove the section.");
        }

        // Zero is legal and means "no calls at all", which is a coherent thing to
        // want (a read-only day, a paused agent). Negative is not.
        if (MaxCalls < 0)
        {
            throw new PolicyException(
                $"'budgets.{scope}.max_calls' cannot be negative (got {MaxCalls}).");
        }

        if (MaxCost < 0)
        {
            throw new PolicyException(
                $"'budgets.{scope}.max_cost' cannot be negative (got {MaxCost}).");
        }
    }
}
