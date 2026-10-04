using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Tests.Upstream;

public class UpstreamNeedsOperatorExceptionTests
{
    [Fact]
    public void Find_SeesAnyCause_NotOnlyOAuth()
    {
        // The registry and the pipeline catch the base type, so a future
        // "renew this credential" failure is handled without either of them
        // learning its name.
        var renew = new UpstreamNeedsOperatorException("vault", "Server 'vault' needs its API key renewed.");

        var found = UpstreamNeedsOperatorException.Find(new HttpRequestException("outer", renew));

        Assert.Same(renew, found);
        Assert.Equal("vault", found!.Server);
    }
}
