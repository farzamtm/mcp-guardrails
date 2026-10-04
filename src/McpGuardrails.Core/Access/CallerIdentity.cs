using System.Security.Claims;

namespace McpGuardrails.Core.Access;

/// <summary>
/// Who made a call, as established by a validated access token.
/// </summary>
/// <param name="Principal">
/// The value of the configured principal claim (<c>sub</c> by default). An
/// identifier, never the token: this is what policy, budgets and the audit log
/// see.
/// </param>
/// <param name="Groups">The values of the configured groups claim, possibly none.</param>
/// <remarks>
/// It travels from the HTTP listener to the call pipeline as a
/// <see cref="ClaimsPrincipal"/>, because that is the only per-request channel
/// the MCP SDK carries from an HTTP request to its tool-call filters. The two
/// claim types below are this proxy's own, so nothing else that happens to set a
/// user on the request can be mistaken for a validated caller.
/// </remarks>
public sealed record CallerIdentity(string Principal, IReadOnlyList<string> Groups)
{
    /// <summary>The authentication type stamped on identities this proxy validated.</summary>
    public const string AuthenticationType = "mcp-guardrails-oauth";

    private const string _principalClaimType = "urn:mcp-guardrails:principal";
    private const string _groupClaimType = "urn:mcp-guardrails:group";

    /// <summary>Packs the identity for the trip through the MCP SDK.</summary>
    public ClaimsPrincipal ToClaimsPrincipal()
    {
        var claims = new List<Claim>(Groups.Count + 1) { new(_principalClaimType, Principal) };
        claims.AddRange(Groups.Select(group => new Claim(_groupClaimType, group)));

        return new ClaimsPrincipal(new ClaimsIdentity(claims, AuthenticationType));
    }

    /// <summary>
    /// Unpacks an identity packed by <see cref="ToClaimsPrincipal"/>, or null when
    /// the request carried none - every stdio call, and every HTTP call without
    /// <c>access.oauth</c>.
    /// </summary>
    public static CallerIdentity? FromClaimsPrincipal(ClaimsPrincipal? user)
    {
        var identity = user?.Identities.FirstOrDefault(
            candidate => candidate.AuthenticationType == AuthenticationType);

        if (identity?.FindFirst(_principalClaimType)?.Value is not { } principal)
        {
            return null;
        }

        return new CallerIdentity(
            principal,
            [.. identity.FindAll(_groupClaimType).Select(claim => claim.Value)]);
    }
}
