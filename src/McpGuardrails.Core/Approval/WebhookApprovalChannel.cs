using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using McpGuardrails.Core.Scanners;
using McpGuardrails.Core.Serialization;

namespace McpGuardrails.Core.Approval;

/// <summary>
/// Asks an HTTP endpoint, for agents with nobody sitting at the client.
/// </summary>
/// <remarks>
/// The protocol is one signed POST, answered synchronously: the endpoint holds
/// the request open until a human decides and replies
/// <c>{"request_id": "...", "decision": "approve"}</c> (or <c>"deny"</c>). That
/// was chosen over "202 now, poll a status URL later" because it is the same
/// shape as every other channel - ask, await, honour the gate's token - so the
/// gate's deadline is simply the request being cancelled. Polling would add a
/// second URL supplied by the remote side, which then needs its own scheme,
/// host and signing checks, to buy something a receiver can do internally.
///
/// Fail closed throughout. Anything other than a well-formed, correlated
/// <c>approve</c> - a status other than 200, a redirect, a body that does not parse,
/// an answer for some other request, an unknown decision, a refused connection -
/// is <see cref="ApprovalOutcome.Failed"/>, which the gate turns into a denial.
/// Only the gate's own deadline produces <see cref="ApprovalOutcome.TimedOut"/>,
/// so a rule's <c>on_timeout</c> means the same thing here as it does in-band.
/// </remarks>
public sealed class WebhookApprovalChannel : IApprovalChannel, IDisposable
{
    /// <summary>Header carrying <c>sha256=&lt;hex HMAC of the raw body&gt;</c>.</summary>
    public const string SignatureHeader = "X-Guardrails-Signature";

    /// <summary>Header repeating the body's <c>request_id</c>, for receivers' logs.</summary>
    public const string RequestIdHeader = "X-Guardrails-Request-Id";

    /// <summary>Longest argument value sent in full; longer ones are cut.</summary>
    /// <remarks>
    /// An approver needs to see which path or which customer, not the 40 KB of
    /// file content being written - and every byte sent is a byte disclosed to
    /// one more system.
    /// </remarks>
    internal const int MaxArgumentLength = 256;

    /// <summary>Largest answer the channel will read.</summary>
    /// <remarks>
    /// A decision is a few dozen bytes. Bounding the read means a broken or
    /// hostile endpoint streaming a huge body costs a failed approval, not the
    /// proxy's memory.
    /// </remarks>
    internal const int MaxAnswerBytes = 64 * 1024;

    private readonly HttpClient _http;
    private readonly Uri _endpoint;
    private readonly byte[] _secret;

    /// <param name="endpoint">Where to POST. Validated by the policy loader, not here.</param>
    /// <param name="secret">The HMAC-SHA256 key.</param>
    /// <param name="handler">The transport; <see cref="CreateHandler"/> in production.</param>
    public WebhookApprovalChannel(Uri endpoint, byte[] secret, HttpMessageHandler handler)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentNullException.ThrowIfNull(handler);

        if (secret.Length == 0)
        {
            throw new ArgumentException("An empty signing secret authenticates nothing.", nameof(secret));
        }

        _endpoint = endpoint;
        _secret = secret;

        _http = new HttpClient(handler, disposeHandler: true)
        {
            // Infinite, because the gate owns the deadline. HttpClient's own
            // 100s default would fire as an OperationCanceledException the gate
            // cannot tell from its deadline, and report a 300s rule as having
            // timed out after 100.
            Timeout = Timeout.InfiniteTimeSpan,
            MaxResponseContentBufferSize = MaxAnswerBytes,
        };
    }

    /// <summary>The production transport.</summary>
    /// <remarks>
    /// Redirects off. A 3xx is a request to send the signed body somewhere the
    /// policy did not name - possibly over plain http - and following it would
    /// bypass every check the loader made on the URL. Not following it makes it
    /// a non-2xx answer, which is a denial.
    /// </remarks>
    public static SocketsHttpHandler CreateHandler() => new()
    {
        AllowAutoRedirect = false,
        // Re-resolve DNS now and then: the process can live as long as the
        // client session, and a receiver behind a load balancer moves.
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    };

    /// <inheritdoc />
    public async ValueTask<ApprovalOutcome> RequestAsync(
        ApprovalRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var body = JsonSerializer.SerializeToUtf8Bytes(
            Payload(request),
            GuardrailsJsonContext.Default.WebhookApprovalPayload);

        using var message = new HttpRequestMessage(HttpMethod.Post, _endpoint)
        {
            Content = new ByteArrayContent(body),
        };
        message.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json", "utf-8");
        message.Headers.Add(SignatureHeader, Sign(body));
        message.Headers.Add(RequestIdHeader, request.RequestId);

        try
        {
            using var response = await _http.SendAsync(message, cancellationToken);

            // 200 exactly. A 202 is "accepted, answer later", which this protocol
            // does not have; a 3xx was not followed (see CreateHandler).
            if (response.StatusCode is not HttpStatusCode.OK)
            {
                return ApprovalOutcome.Failed;
            }

            // Already buffered by SendAsync, within MaxResponseContentBufferSize.
            var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            var answer = JsonSerializer.Deserialize(
                bytes,
                GuardrailsJsonContext.Default.WebhookApprovalAnswer);

            return Interpret(answer, request.RequestId);
        }
        catch (HttpRequestException)
        {
            // DNS, TLS, refused connection, oversized body: the question was not
            // answered, and an unanswered security question is a no.
            return ApprovalOutcome.Failed;
        }
        catch (JsonException)
        {
            return ApprovalOutcome.Failed;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // A cancellation that is not ours - the transport giving up on its
            // own. Letting it escape would have the gate label it TimedOut, and a
            // rule with on_timeout: allow would then approve a call nobody saw.
            return ApprovalOutcome.Failed;
        }
    }

    /// <inheritdoc />
    public void Dispose() => _http.Dispose();

    /// <summary>Computes the signature header value for a body.</summary>
    /// <remarks>
    /// Over the exact bytes sent, so a receiver verifies before parsing and never
    /// has to reproduce this serializer's formatting.
    /// </remarks>
    internal string Sign(byte[] body) =>
        "sha256=" + Convert.ToHexStringLower(HMACSHA256.HashData(_secret, body));

    /// <summary>Shortens arguments to what an approver needs to see.</summary>
    /// <remarks>
    /// Secrets are redacted whatever <c>scanners.secrets</c> says, because the
    /// endpoint is one more system outside the proxy and an approver decides on
    /// the path and the shape of a call, never on a key's value. Redacted before
    /// the cut, so truncation cannot leave half a key the detectors no longer
    /// recognise. PII is left alone: "which customer" is often the question.
    /// </remarks>
    internal static IReadOnlyDictionary<string, string>? Summarize(
        IReadOnlyDictionary<string, JsonElement>? arguments)
    {
        if (arguments is null)
        {
            return null;
        }

        var summary = new Dictionary<string, string>(arguments.Count, StringComparer.Ordinal);

        foreach (var (name, value) in arguments)
        {
            // Strings unquoted, so a path reads as a path; anything else as the
            // JSON the model sent, so an object or a number is not misrepresented.
            var text = value.ValueKind is JsonValueKind.String
                ? value.GetString()!
                : value.GetRawText();

            summary[name] = Truncate(SecretScanner.Redact(text, includePii: false).Text);
        }

        return summary;
    }

    private static string Truncate(string text)
    {
        if (text.Length <= MaxArgumentLength)
        {
            return text;
        }

        // Never split a surrogate pair: half of one is not a character, and the
        // receiver would get a replacement glyph or a decoding error instead.
        var cut = char.IsHighSurrogate(text[MaxArgumentLength - 1])
            ? MaxArgumentLength - 1
            : MaxArgumentLength;

        return $"{text[..cut]}... ({text.Length - cut} more characters)";
    }

    private static WebhookApprovalPayload Payload(ApprovalRequest request) => new()
    {
        RequestId = request.RequestId,
        Tool = request.Tool,
        Server = request.Server,
        Rule = request.RuleName,
        Question = request.Question,
        Arguments = Summarize(request.Arguments),
        SentAt = DateTimeOffset.UtcNow,
        Deadline = request.Deadline,
    };

    /// <remarks>
    /// The request id has to come back. Without it, an endpoint that caches
    /// responses, or a receiver that answers the wrong pending question, could
    /// approve this call with someone's "yes" to another one.
    /// </remarks>
    private static ApprovalOutcome Interpret(WebhookApprovalAnswer? answer, string requestId)
    {
        if (answer is null || !string.Equals(answer.RequestId, requestId, StringComparison.Ordinal))
        {
            return ApprovalOutcome.Failed;
        }

        // Exact and case-sensitive: consent is "approve", not anything that
        // looks a bit like it.
        return answer.Decision switch
        {
            "approve" => ApprovalOutcome.Approved,
            "deny" => ApprovalOutcome.Declined,
            _ => ApprovalOutcome.Failed,
        };
    }
}
