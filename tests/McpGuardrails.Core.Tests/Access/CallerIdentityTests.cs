using System.Security.Claims;
using McpGuardrails.Core.Access;

namespace McpGuardrails.Core.Tests.Access;

public sealed class CallerIdentityTests
{
    [Fact]
    public void AnIdentity_SurvivesTheTripThroughAClaimsPrincipal()
    {
        var caller = new CallerIdentity("alice", ["admins", "engineering"]);

        var back = CallerIdentity.FromClaimsPrincipal(caller.ToClaimsPrincipal());

        Assert.Equal("alice", back!.Principal);
        Assert.Equal(["admins", "engineering"], back.Groups);
    }

    [Fact]
    public void NoUser_IsNoCaller()
    {
        Assert.Null(CallerIdentity.FromClaimsPrincipal(null));
        Assert.Null(CallerIdentity.FromClaimsPrincipal(new ClaimsPrincipal()));
    }

    [Fact]
    public void AUserSetBySomethingElse_IsNotACaller()
    {
        // Only identities this proxy validated count, whatever claims they carry.
        var other = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("urn:mcp-guardrails:principal", "mallory")], "Cookies"));

        Assert.Null(CallerIdentity.FromClaimsPrincipal(other));
    }

    [Fact]
    public void AnIdentityOfTheRightTypeWithoutAPrincipal_IsNotACaller()
    {
        var empty = new ClaimsPrincipal(new ClaimsIdentity([], CallerIdentity.AuthenticationType));

        Assert.Null(CallerIdentity.FromClaimsPrincipal(empty));
    }
}
