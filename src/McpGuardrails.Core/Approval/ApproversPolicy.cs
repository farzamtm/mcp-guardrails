using System.Text;
using System.Text.Json.Serialization;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Approval;

/// <summary>
/// The <c>approvers:</c> section of a policy file: where out-of-band questions go.
/// </summary>
/// <remarks>
/// Top level rather than inside each rule's <c>approval:</c> block. A rule says
/// <em>whether</em> and <em>how long</em> to ask, which differs per rule; the
/// endpoint is a property of the deployment, and repeating a URL on every rule is
/// how two rules end up quietly asking different services.
/// </remarks>
public sealed record ApproversPolicy
{
    /// <summary>No out-of-band approver configured.</summary>
    public static ApproversPolicy None { get; } = new();

    /// <summary>The HTTP endpoint asked by <c>mode: webhook</c> rules.</summary>
    [JsonPropertyName("webhook")]
    public WebhookApproverSettings? Webhook { get; init; }

    /// <summary>Validates the section against the rules that will use it.</summary>
    public void Validate(IReadOnlyList<PolicyRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);

        if (Webhook is not null)
        {
            Webhook.Validate();
            return;
        }

        // A webhook rule with nowhere to send the question would deny every call
        // at runtime with "the approval channel is broken". The operator made a
        // configuration mistake, so tell them at startup, in their own terms.
        var orphan = rules.FirstOrDefault(
            rule => rule.Approval?.EffectiveMode is ApprovalMode.Webhook);

        if (orphan is not null)
        {
            throw new PolicyException(
                $"Rule '{orphan.Name}' asks for 'webhook' approval, but the policy has no " +
                "'approvers.webhook' section saying where to send the question. Add one with " +
                "a 'url' and a 'secret_env'.");
        }
    }
}

/// <summary>
/// The <c>approvers.webhook:</c> block.
/// </summary>
/// <remarks>
/// Holds the <em>name</em> of the environment variable that carries the signing
/// secret, never the secret: policy files get committed, pasted into issues and
/// shown on screen, and a secret that lives in one is a secret that has leaked.
/// </remarks>
public sealed record WebhookApproverSettings
{
    /// <summary>The endpoint the approval request is POSTed to.</summary>
    [JsonPropertyName("url")]
    public string? Url { get; init; }

    /// <summary>The environment variable holding the HMAC-SHA256 signing secret.</summary>
    [JsonPropertyName("secret_env")]
    public string? SecretEnv { get; init; }

    /// <summary>Permit plain <c>http://</c>, and only to a loopback address.</summary>
    /// <remarks>
    /// For a receiver running on the same machine during development. Scoped to
    /// loopback in its very name, so nobody reads it as "allow http" and points it
    /// at a host where the approval - and the arguments in it - cross a network
    /// in the clear and can be answered by whoever is on the path.
    /// </remarks>
    [JsonPropertyName("allow_insecure_localhost")]
    public bool? AllowInsecureLocalhost { get; init; }

    /// <summary>The validated endpoint. Only meaningful after <see cref="Validate"/>.</summary>
    [JsonIgnore]
    public Uri Endpoint => new(Url!, UriKind.Absolute);

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(Url))
        {
            throw new PolicyException("'approvers.webhook' needs a 'url' to send approval requests to.");
        }

        if (!Uri.TryCreate(Url, UriKind.Absolute, out var uri))
        {
            throw new PolicyException(
                $"'approvers.webhook.url' ('{Url}') is not an absolute URL.");
        }

        // Credentials in the URL are a secret in the policy file by another name.
        if (uri.UserInfo.Length > 0)
        {
            throw new PolicyException(
                "'approvers.webhook.url' contains credentials. Keep secrets out of the policy " +
                "file; the request is authenticated by its signature (see 'secret_env').");
        }

        ValidateScheme(uri);

        if (string.IsNullOrWhiteSpace(SecretEnv))
        {
            throw new PolicyException(
                "'approvers.webhook' needs a 'secret_env' naming the environment variable that " +
                "holds the signing secret. Unsigned approval requests are not supported.");
        }

        // Also the cheapest guard against the commonest mistake: pasting the
        // secret itself here. Random secrets tend to contain '-', '+', '/' or
        // '=', none of which an environment variable name can.
        if (!IsEnvironmentVariableName(SecretEnv))
        {
            throw new PolicyException(
                "'approvers.webhook.secret_env' must be the NAME of an environment variable " +
                "(letters, digits and '_', not starting with a digit) - not the secret itself.");
        }
    }

    /// <summary>Reads the signing secret from the environment.</summary>
    /// <param name="environment">Looks a variable up by name; injectable for tests.</param>
    /// <remarks>
    /// Separate from <see cref="Validate"/>, and called only when the proxy is
    /// about to serve, so a policy file can be checked on a machine that does not
    /// hold the secret (CI validates every example this way).
    /// </remarks>
    public byte[] ReadSecret(Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(environment);

        var secret = environment(SecretEnv!);

        // Fatal rather than "sign with an empty key": a signature anyone can
        // forge authenticates nothing, and every receiver following the README
        // would accept it.
        if (string.IsNullOrEmpty(secret))
        {
            throw new PolicyException(
                $"'approvers.webhook.secret_env' names '{SecretEnv}', which is not set or is " +
                "empty. Export the webhook signing secret in that variable before starting the " +
                "proxy.");
        }

        return Encoding.UTF8.GetBytes(secret);
    }

    private void ValidateScheme(Uri uri)
    {
        if (uri.Scheme == Uri.UriSchemeHttps)
        {
            return;
        }

        if (uri.Scheme != Uri.UriSchemeHttp)
        {
            throw new PolicyException(
                $"'approvers.webhook.url' uses '{uri.Scheme}'. Use https.");
        }

        if (AllowInsecureLocalhost is not true)
        {
            throw new PolicyException(
                "'approvers.webhook.url' uses plain http. Approval requests carry the call's " +
                "arguments and the answer decides whether it runs, so use https - or, for a " +
                "receiver on this machine only, set 'allow_insecure_localhost: true'.");
        }

        if (!uri.IsLoopback)
        {
            throw new PolicyException(
                $"'approvers.webhook.url' uses plain http to '{uri.Host}', but " +
                "'allow_insecure_localhost' only permits loopback addresses (localhost, " +
                "127.0.0.1, ::1). Use https for anything else.");
        }
    }

    private static bool IsEnvironmentVariableName(string name)
    {
        if (char.IsAsciiDigit(name[0]))
        {
            return false;
        }

        foreach (var c in name)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c == '_'))
            {
                return false;
            }
        }

        return true;
    }
}
