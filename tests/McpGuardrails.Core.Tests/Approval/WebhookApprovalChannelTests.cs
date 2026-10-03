using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using McpGuardrails.Core.Approval;
using McpGuardrails.Core.Policy;
using McpGuardrails.Core.Scanners;
using McpGuardrails.Core.Tests.Policy;

namespace McpGuardrails.Core.Tests.Approval;

/// <summary>
/// The webhook channel against a fake transport. No sockets: every behaviour
/// worth testing is a function of what the endpoint answers.
/// </summary>
public sealed class WebhookApprovalChannelTests
{
    private static readonly Uri _endpoint = new("https://approvals.example.com/hooks/guardrails");
    private static readonly byte[] _secret = Encoding.UTF8.GetBytes("test-signing-secret");

    /// <summary>Answers however the test says, and keeps what it was sent.</summary>
    private sealed class FakeHandler(
        Func<HttpRequestMessage, string, CancellationToken, Task<HttpResponseMessage>> respond)
        : HttpMessageHandler
    {
        public HttpRequestMessage? Request { get; private set; }

        public string? Body { get; private set; }

        public bool Disposed { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Request = request;
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            return await respond(request, Body, cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }

    private static string RequestIdOf(string body)
    {
        using var json = JsonDocument.Parse(body);
        return json.RootElement.GetProperty("request_id").GetString()!;
    }

    /// <summary>A receiver that echoes the request id with the given decision.</summary>
    private static FakeHandler Decides(string decision) => new((_, body, _) =>
        Task.FromResult(Json(HttpStatusCode.OK, $$"""
            {"request_id": "{{RequestIdOf(body)}}", "decision": "{{decision}}"}
            """)));

    private static FakeHandler Replies(HttpStatusCode status, string body) =>
        new((_, _, _) => Task.FromResult(Json(status, body)));

    private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static WebhookApprovalChannel Channel(HttpMessageHandler handler, SecretScannerSettings? redaction = null) =>
        new(_endpoint, _secret, handler, redaction ?? SecretScannerSettings.Default);

    private static ApprovalRequest Request(
        IReadOnlyDictionary<string, JsonElement>? arguments = null,
        string? server = "fs") =>
        new("fs__delete_file", "approve-deletes", "Delete a file?")
        {
            Mode = ApprovalMode.Webhook,
            RequestId = "3f2a9c",
            Deadline = new DateTimeOffset(2026, 10, 1, 12, 5, 0, TimeSpan.Zero),
            Server = server,
            Arguments = arguments,
        };

    private static async Task<ApprovalOutcome> Ask(HttpMessageHandler handler, ApprovalRequest? request = null)
    {
        using var channel = Channel(handler);
        return await channel.RequestAsync(request ?? Request(), CancellationToken.None);
    }

    // ---------------------------------------------------------------- answers

    [Fact]
    public async Task Approve_IsApproved()
    {
        Assert.Equal(ApprovalOutcome.Approved, await Ask(Decides("approve")));
    }

    [Fact]
    public async Task Deny_IsDeclined()
    {
        Assert.Equal(ApprovalOutcome.Declined, await Ask(Decides("deny")));
    }

    [Theory]
    [InlineData("APPROVE")]
    [InlineData("yes")]
    [InlineData("")]
    public async Task AnythingButAnExactDecision_Fails(string decision)
    {
        // Consent is "approve", not anything resembling it.
        Assert.Equal(ApprovalOutcome.Failed, await Ask(Decides(decision)));
    }

    [Fact]
    public async Task AMissingDecision_Fails()
    {
        var handler = new FakeHandler((_, body, _) =>
            Task.FromResult(Json(HttpStatusCode.OK, $$"""{"request_id": "{{RequestIdOf(body)}}"}""")));

        Assert.Equal(ApprovalOutcome.Failed, await Ask(handler));
    }

    [Theory]
    [InlineData("""{"request_id": "someone-elses", "decision": "approve"}""")]
    [InlineData("""{"decision": "approve"}""")]
    public async Task AnApprovalForAnotherRequest_Fails(string body)
    {
        // A caching proxy or a confused receiver must not be able to approve
        // this call with a "yes" that belonged to a different one.
        Assert.Equal(ApprovalOutcome.Failed, await Ask(Replies(HttpStatusCode.OK, body)));
    }

    [Theory]
    [InlineData(HttpStatusCode.Created)]
    [InlineData(HttpStatusCode.Accepted)]
    [InlineData(HttpStatusCode.Found)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task AnythingButOk_FailsEvenWithAnApprovingBody(HttpStatusCode status)
    {
        // 202 included: the protocol is synchronous, so "accepted, answer later"
        // is not an answer. And a 3xx is never followed - see CreateHandler.
        var handler = new FakeHandler((_, body, _) => Task.FromResult(Json(
            status,
            $$"""{"request_id": "{{RequestIdOf(body)}}", "decision": "approve"}""")));

        Assert.Equal(ApprovalOutcome.Failed, await Ask(handler));
    }

    [Theory]
    [InlineData("")]
    [InlineData("null")]
    [InlineData("approve")]
    [InlineData("""{"request_id": 3, "decision": "approve"}""")]
    public async Task ABodyThatIsNotAnAnswer_Fails(string body)
    {
        Assert.Equal(ApprovalOutcome.Failed, await Ask(Replies(HttpStatusCode.OK, body)));
    }

    [Fact]
    public async Task AnOversizedAnswer_FailsRatherThanBeingRead()
    {
        var padding = new string(' ', WebhookApprovalChannel.MaxAnswerBytes + 1);

        Assert.Equal(
            ApprovalOutcome.Failed,
            await Ask(Replies(HttpStatusCode.OK, padding + """{"decision": "approve"}""")));
    }

    // ------------------------------------------------------- transport faults

    [Fact]
    public async Task ATransportError_Fails()
    {
        var handler = new FakeHandler((_, _, _) =>
            throw new HttpRequestException("Connection refused"));

        Assert.Equal(ApprovalOutcome.Failed, await Ask(handler));
    }

    [Fact]
    public async Task ACancellationThatIsNotTheGates_Fails()
    {
        // If this escaped, the gate would call it a timeout, and a rule with
        // on_timeout: allow would approve a call nobody looked at.
        var handler = new FakeHandler((_, _, _) =>
            throw new TaskCanceledException("the transport gave up"));

        Assert.Equal(ApprovalOutcome.Failed, await Ask(handler));
    }

    [Fact]
    public async Task TheGatesCancellation_Propagates()
    {
        var handler = new FakeHandler(async (_, _, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            throw new InvalidOperationException("unreachable");
        });
        using var channel = Channel(handler);
        using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await channel.RequestAsync(Request(), deadline.Token));
    }

    [Fact]
    public async Task AnEndpointThatNeverAnswers_IsAGateTimeout_AndHonoursOnTimeout()
    {
        // The whole point of the gate owning the deadline: a silent webhook
        // means exactly what a silent human at the client means.
        var handler = new FakeHandler(async (_, _, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            throw new InvalidOperationException("unreachable");
        });
        using var channel = Channel(handler);
        var decision = new Decision(Verdict.RequireApproval, "ask", "approve-deletes")
        {
            Approval = new ApprovalSettings { Mode = ApprovalMode.Webhook, TimeoutSeconds = 1 },
        };

        var result = await ApprovalGate.ApplyAsync(decision, new ToolCallFacts("fs__delete_file"), channel);

        Assert.Equal(ApprovalOutcome.TimedOut, result.ApprovalResult);
        Assert.Equal(Verdict.Deny, result.Verdict);
    }

    // ------------------------------------------------------------ the request

    [Fact]
    public async Task TheRequest_IsASignedJsonPost()
    {
        var handler = Decides("approve");

        await Ask(handler);

        var request = handler.Request!;
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(_endpoint, request.RequestUri);
        Assert.Equal("application/json", request.Content!.Headers.ContentType!.MediaType);
        Assert.Equal("utf-8", request.Content.Headers.ContentType.CharSet);

        // Recomputed independently, the way a receiver would.
        var expected = "sha256=" + Convert.ToHexStringLower(
            HMACSHA256.HashData(_secret, Encoding.UTF8.GetBytes(handler.Body!)));

        Assert.Equal(
            expected,
            Assert.Single(request.Headers.GetValues(WebhookApprovalChannel.SignatureHeader)));
        Assert.Equal(
            "3f2a9c",
            Assert.Single(request.Headers.GetValues(WebhookApprovalChannel.RequestIdHeader)));
    }

    [Fact]
    public async Task TheSignature_ChangesWithTheSecret()
    {
        var handler = Decides("approve");
        using var channel = new WebhookApprovalChannel(
            _endpoint, Encoding.UTF8.GetBytes("other"), handler, SecretScannerSettings.Default);

        await channel.RequestAsync(Request(), CancellationToken.None);

        var body = Encoding.UTF8.GetBytes(handler.Body!);
        using var reference = Channel(Decides("approve"));

        Assert.NotEqual(
            reference.Sign(body),
            Assert.Single(handler.Request!.Headers.GetValues(WebhookApprovalChannel.SignatureHeader)));
    }

    [Fact]
    public async Task TheBody_CarriesTheDocumentedFields()
    {
        var handler = Decides("approve");
        var before = DateTimeOffset.UtcNow;

        await Ask(handler, Request(TestArguments.From("""{"path": "/srv/a.txt", "force": true}""")));

        using var json = JsonDocument.Parse(handler.Body!);
        var root = json.RootElement;

        Assert.Equal(1, root.GetProperty("version").GetInt32());
        Assert.Equal("3f2a9c", root.GetProperty("request_id").GetString());
        Assert.Equal("fs__delete_file", root.GetProperty("tool").GetString());
        Assert.Equal("fs", root.GetProperty("server").GetString());
        Assert.Equal("approve-deletes", root.GetProperty("rule").GetString());
        Assert.Equal("Delete a file?", root.GetProperty("question").GetString());
        Assert.Equal("/srv/a.txt", root.GetProperty("arguments").GetProperty("path").GetString());
        Assert.Equal("true", root.GetProperty("arguments").GetProperty("force").GetString());
        Assert.Equal(
            new DateTimeOffset(2026, 10, 1, 12, 5, 0, TimeSpan.Zero),
            root.GetProperty("deadline").GetDateTimeOffset());
        Assert.InRange(root.GetProperty("sent_at").GetDateTimeOffset(), before, DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task TheBody_RedactsSensitiveFieldsAndPersonalData_AsThePolicyConfigures()
    {
        // The receiver is outside the proxy and keeps what it is sent, so it gets
        // the same redaction the audit log does - including pii: true.
        var handler = Decides("approve");
        using var channel = Channel(handler, new SecretScannerSettings { Pii = true });

        await channel.RequestAsync(
            Request(TestArguments.From("""{"password": "correcthorse", "to": "ada@example.com"}""")),
            CancellationToken.None);

        using var json = JsonDocument.Parse(handler.Body!);
        var arguments = json.RootElement.GetProperty("arguments");

        Assert.DoesNotContain("correcthorse", handler.Body!, StringComparison.Ordinal);
        Assert.DoesNotContain("ada@example.com", handler.Body!, StringComparison.Ordinal);
        Assert.Equal(
            SecretScanner.Marker(SecretScanner.SensitiveField),
            arguments.GetProperty("password").GetString());
        Assert.Equal(SecretScanner.Marker(SecretScanner.Email), arguments.GetProperty("to").GetString());
    }

    [Fact]
    public async Task AbsentContext_IsOmittedRatherThanSentAsNull()
    {
        var handler = Decides("approve");

        await Ask(handler, Request(arguments: null, server: null));

        using var json = JsonDocument.Parse(handler.Body!);

        Assert.False(json.RootElement.TryGetProperty("arguments", out _));
        Assert.False(json.RootElement.TryGetProperty("server", out _));
    }

    // -------------------------------------------------------------- plumbing

    [Fact]
    public void TheProductionHandler_DoesNotFollowRedirects()
    {
        // A redirect would send the signed body somewhere the policy did not
        // name, possibly over plain http, past every check on the URL.
        using var handler = WebhookApprovalChannel.CreateHandler();

        Assert.False(handler.AllowAutoRedirect);
    }

    [Fact]
    public void Disposing_ReleasesTheTransport()
    {
        var handler = Decides("approve");

        Channel(handler).Dispose();

        Assert.True(handler.Disposed);
    }

    [Fact]
    public async Task Arguments_AreRequired()
    {
        using var handler = Decides("approve");

        Assert.Throws<ArgumentNullException>(() => new WebhookApprovalChannel(null!, _secret, handler, SecretScannerSettings.Default));
        Assert.Throws<ArgumentNullException>(() => new WebhookApprovalChannel(_endpoint, null!, handler, SecretScannerSettings.Default));
        Assert.Throws<ArgumentNullException>(() => new WebhookApprovalChannel(_endpoint, _secret, null!, SecretScannerSettings.Default));
        Assert.Throws<ArgumentException>(() => new WebhookApprovalChannel(_endpoint, [], handler, SecretScannerSettings.Default));
        Assert.Throws<ArgumentNullException>(() => new WebhookApprovalChannel(_endpoint, _secret, handler, null!));

        using var channel = Channel(Decides("approve"));
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await channel.RequestAsync(null!, CancellationToken.None));
    }
}
