using System.Net;
using System.Text;
using System.Text.Json;
using McpGuardrails.Core.Approval;
using McpGuardrails.Core.LocalUi;
using McpGuardrails.Core.Scanners;

namespace McpGuardrails.Core.Tests.LocalUi;

/// <summary>
/// The local UI channel against a fake transport. It is a thin router onto
/// <see cref="WebhookApprovalChannel"/>, so these tests cover locating the UI and
/// delegating to it, not the wire protocol itself - that is
/// <c>WebhookApprovalChannelTests</c>.
/// </summary>
public sealed class LocalUiApprovalChannelTests
{
    private static readonly UiEndpoint _endpoint = new(
        new Uri("http://127.0.0.1:53817/"),
        Encoding.UTF8.GetBytes("0123456789abcdef"));

    private sealed class FakeHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond)
        : HttpMessageHandler
    {
        public HttpRequestMessage? Request { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Request = request;
            return await respond(request);
        }
    }

    private static ApprovalRequest Request() =>
        new("fs__delete_file", "approve-deletes", "Delete a file?") { Mode = ApprovalMode.LocalUi };

    [Fact]
    public async Task NoRendezvousFile_IsUnavailable_WithoutTouchingTheNetwork()
    {
        var asked = false;
        var handler = new FakeHandler(_ =>
        {
            asked = true;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });

        var channel = new LocalUiApprovalChannel(() => null, SecretScannerSettings.Default, () => handler);

        var outcome = await channel.RequestAsync(Request(), CancellationToken.None);

        Assert.Equal(ApprovalOutcome.Unavailable, outcome);
        Assert.False(asked, "a missing UI must never reach the network");
    }

    [Fact]
    public async Task ARunningUi_IsAskedAtItsApprovalsUrl()
    {
        var channel = new LocalUiApprovalChannel(
            () => _endpoint,
            SecretScannerSettings.Default,
            () => new FakeHandler(request =>
            {
                var requestId = RequestIdOf(request);
                return Task.FromResult(Json($$"""
                    {"request_id": "{{requestId}}", "decision": "approve"}
                    """));
            }));

        var outcome = await channel.RequestAsync(Request(), CancellationToken.None);

        Assert.Equal(ApprovalOutcome.Approved, outcome);
    }

    [Fact]
    public async Task TheRequestGoesToTheEndpointsOwnApprovalsPath()
    {
        HttpRequestMessage? sent = null;
        var channel = new LocalUiApprovalChannel(
            () => _endpoint,
            SecretScannerSettings.Default,
            () => new FakeHandler(request =>
            {
                sent = request;
                return Task.FromResult(Json($$"""
                    {"request_id": "{{RequestIdOf(request)}}", "decision": "deny"}
                    """));
            }));

        await channel.RequestAsync(Request(), CancellationToken.None);

        Assert.Equal(_endpoint.ApprovalsUrl, sent!.RequestUri);
    }

    [Fact]
    public async Task ADeniedAnswer_IsDeclined()
    {
        var channel = new LocalUiApprovalChannel(
            () => _endpoint,
            SecretScannerSettings.Default,
            () => new FakeHandler(request => Task.FromResult(Json($$"""
                {"request_id": "{{RequestIdOf(request)}}", "decision": "deny"}
                """))));

        var outcome = await channel.RequestAsync(Request(), CancellationToken.None);

        Assert.Equal(ApprovalOutcome.Declined, outcome);
    }

    [Fact]
    public void Arguments_AreRequired()
    {
        Assert.Throws<ArgumentNullException>(
            () => new LocalUiApprovalChannel(null!, SecretScannerSettings.Default, () => new FakeHandler(_ => throw new UnreachableException())));
        Assert.Throws<ArgumentNullException>(
            () => new LocalUiApprovalChannel(() => _endpoint, null!, () => new FakeHandler(_ => throw new UnreachableException())));
        Assert.Throws<ArgumentNullException>(
            () => new LocalUiApprovalChannel(() => _endpoint, SecretScannerSettings.Default, null!));
    }

    private sealed class UnreachableException : Exception;

    private static string RequestIdOf(HttpRequestMessage request)
    {
        var body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
        using var json = JsonDocument.Parse(body);
        return json.RootElement.GetProperty("request_id").GetString()!;
    }

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
