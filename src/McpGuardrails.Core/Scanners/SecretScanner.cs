using System.Buffers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace McpGuardrails.Core.Scanners;

/// <summary>
/// Finds credentials and personal data in text and JSON, and replaces them with
/// markers that say what was removed.
/// </summary>
/// <remarks>
/// The threat runs both ways through the proxy. On the way IN, a tool result is
/// how a secret reaches the model: a <c>.env</c> file read for debugging, a CI
/// log, a config dump. Once the model has read it, it has been sent to the model
/// provider and written into every transcript, and nothing downstream can take
/// it back. On the way OUT, arguments are how a secret leaves: an agent pasting a
/// key into an issue comment, or an injected instruction asking it to. And the
/// proxy's own audit log, which records every argument, would otherwise be the
/// best-organised file of API keys on the machine.
///
/// Two implementation choices worth defending:
///
/// <b>Regular expressions, but only the non-backtracking engine.</b> The
/// injection scanner avoids regex altogether by matching normalised tokens. That
/// does not work here: a secret is defined by its exact shape - a prefix, a
/// length, an alphabet - and normalising would destroy precisely what identifies
/// it. So the patterns are real regexes, constructed with
/// <see cref="RegexOptions.NonBacktracking"/>. That engine simulates the
/// pattern as an automaton and is guaranteed linear in the input, so a
/// megabyte of attacker-chosen result text cannot stall a call, and there is no
/// timeout to tune because there is nothing for one to catch. The cost is a
/// smaller feature set - no lookarounds, no backreferences - which is why the
/// few checks that need context (a Luhn digit, a following parenthesis) are
/// done in code after the match instead of in the pattern.
///
/// <b>Markers, not deletions.</b> A secret is replaced with
/// <c>[REDACTED:aws-access-key]</c> rather than removed or starred out. The model
/// can then still reason about the text - "the config sets an AWS key" - and can
/// tell the user what it did not see, which a silent gap would hide from both.
/// </remarks>
public static class SecretScanner
{
    /// <summary>A PEM or PGP private key block.</summary>
    public const string PrivateKey = "private-key";

    /// <summary>A JSON Web Token.</summary>
    public const string Jwt = "jwt";

    /// <summary>An AWS access key id.</summary>
    public const string AwsAccessKey = "aws-access-key";

    /// <summary>A GitHub personal access, OAuth, app or fine-grained token.</summary>
    public const string GitHubToken = "github-token";

    /// <summary>A Slack bot, user or app token.</summary>
    public const string SlackToken = "slack-token";

    /// <summary>A Slack incoming-webhook URL, which is itself the credential.</summary>
    public const string SlackWebhook = "slack-webhook";

    /// <summary>A Stripe secret or restricted key.</summary>
    public const string StripeKey = "stripe-key";

    /// <summary>An Anthropic API key.</summary>
    public const string AnthropicKey = "anthropic-key";

    /// <summary>An OpenAI API key.</summary>
    public const string OpenAiKey = "openai-key";

    /// <summary>A Google API key.</summary>
    public const string GoogleApiKey = "google-api-key";

    /// <summary>The token half of an HTTP bearer credential.</summary>
    public const string BearerToken = "bearer-token";

    /// <summary>The value in <c>password=...</c>, <c>api_key: ...</c> and their relatives.</summary>
    public const string CredentialAssignment = "credential-assignment";

    /// <summary>A JSON string under a key such as <c>password</c> or <c>client_secret</c>.</summary>
    public const string SensitiveField = "sensitive-field";

    /// <summary>An email address. Personal data; only with <c>pii: true</c>.</summary>
    public const string Email = "email";

    /// <summary>A payment card number that passes the Luhn check. Only with <c>pii: true</c>.</summary>
    public const string CreditCard = "credit-card";

    private const string _secretGroup = "secret";

    private const string _markerPrefix = "[REDACTED:";

    private const RegexOptions _options = RegexOptions.NonBacktracking | RegexOptions.CultureInvariant;

    /// <param name="Name">What the marker and the audit log call it.</param>
    /// <param name="Pattern">
    /// The shape. When it has a group named <c>secret</c>, only that group is
    /// redacted, so <c>Authorization: Bearer [REDACTED:bearer-token]</c> keeps
    /// the part that tells a reader what kind of value was there.
    /// </param>
    /// <param name="IsPii">Personal data rather than a credential: opt-in.</param>
    /// <param name="Accept">A check the pattern cannot express, run on each match.</param>
    private sealed record Detector(
        string Name,
        Regex Pattern,
        bool IsPii = false,
        Func<string, Group, bool>? Accept = null);

    /// <summary>
    /// Every detector, most specific first.
    /// </summary>
    /// <remarks>
    /// The order is the tie-break when two detectors claim the same text: a
    /// GitHub token assigned to <c>api_key=</c> is reported as a GitHub token,
    /// which is the more useful thing for an operator to read in the log.
    ///
    /// Lower bounds only, never upper ones (<c>{36,}</c>, not <c>{36,255}</c>).
    /// The non-backtracking engine unrolls a counted repetition into states, so a
    /// large upper bound costs memory for no benefit: a longer run of the same
    /// alphabet is still the same secret.
    /// </remarks>
    private static readonly Detector[] _detectors =
    [
        // The body is "anything that is not a run of five dashes", spelled
        // without a lookahead: a dash run of one to four followed by something
        // else. Old-style PEM headers (Proc-Type, DEK-Info) contain single dashes,
        // so a plain [^-]* would stop at the first header and leak the key below
        // it. The END line is optional on purpose: a key truncated by a paginated
        // read is still a key, and the redaction runs to the end of the text.
        new(PrivateKey, new Regex(
            "-----BEGIN[ A-Z0-9]*PRIVATE KEY[ A-Z]*-----(?:[^-]|-{1,4}[^-])*" +
            "(?:-----END[ A-Z0-9]*PRIVATE KEY[ A-Z]*-----)?",
            _options)),

        // Header and payload are base64url JSON objects, so both start "eyJ" -
        // which is what makes this specific enough to run over prose.
        new(Jwt, new Regex(
            @"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*",
            _options)),

        new(AwsAccessKey, new Regex(@"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b", _options)),

        new(GitHubToken, new Regex(
            @"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b",
            _options)),

        new(SlackToken, new Regex(@"\bxox[abposr]-[A-Za-z0-9-]{10,}", _options)),

        new(SlackWebhook, new Regex(
            @"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{20,}",
            _options)),

        // Secret (sk_) and restricted (rk_) keys only. A publishable key (pk_) is
        // designed to be embedded in web pages; redacting it would be noise.
        new(StripeKey, new Regex(@"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b", _options)),

        // Ahead of OpenAI, whose broader "sk-" pattern also matches these.
        new(AnthropicKey, new Regex(@"\bsk-ant-[A-Za-z0-9_-]{20,}", _options)),

        // "sk-" followed by twenty identifier characters is also the shape of a
        // long hyphenated package name (sk-learn-...). Real keys are random and
        // contain digits; names almost never do.
        new(OpenAiKey, new Regex(
            @"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}",
            _options), Accept: ContainsDigit),

        new(GoogleApiKey, new Regex(@"\bAIza[A-Za-z0-9_-]{35,}", _options)),

        // The digit check is what keeps "bearer" in prose from matching: "the
        // bearer responsibilities" is sixteen letters, a token is random.
        new(BearerToken, new Regex(
            @"(?i)\bbearer[ \t]+(?<secret>[A-Za-z0-9._~+/-]{16,}=*)",
            _options), Accept: ContainsDigit),

        // No leading \b, so db_password= and AWS_SECRET_ACCESS_KEY= match: an
        // underscore is a word character, and a boundary would demand the key
        // start the identifier. Three value shapes share one group name: double
        // quoted, single quoted, and bare - the last needing a second look in
        // code because it is also the shape of `password = get_password()`.
        new(CredentialAssignment, new Regex(
            "(?i)(?:password|passwd|passphrase|secret|api[_-]?key|access[_-]?key|" +
            "access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?key)" +
            @"[""']?[ \t]*[:=]>?[ \t]*" +
            @"(?:""(?<secret>[^""\s]{4,})""|'(?<secret>[^'\s]{4,})'|" +
            @"(?<secret>[^\s""'`,;&(){}\[\]<>]{6,}))",
            _options), Accept: IsCredentialValue),

        new(CreditCard, new Regex(@"\b[0-9](?:[ -]?[0-9]){12,18}\b", _options),
            IsPii: true, Accept: IsCardNumber),

        new(Email, new Regex(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", _options),
            IsPii: true),
    ];

    /// <summary>
    /// JSON keys whose string values are secrets whatever they look like.
    /// </summary>
    /// <remarks>
    /// The patterns above recognise a secret by its shape; this recognises one by
    /// its label, which catches the human-chosen password no pattern could. Keys
    /// are compared with case and separators folded away, so <c>clientSecret</c>,
    /// <c>client_secret</c> and <c>Client-Secret</c> are one entry.
    ///
    /// A bare <c>token</c> is deliberately absent: pagination cursors, tokenizer
    /// output and CSRF nonces all use the word, and redacting a cursor breaks the
    /// next page.
    /// </remarks>
    private static readonly HashSet<string> _sensitiveFields = new(StringComparer.Ordinal)
    {
        "password", "passwd", "passphrase", "secret", "clientsecret", "secretkey",
        "secretaccesskey", "apikey", "xapikey", "accesskey", "accesstoken",
        "refreshtoken", "authtoken", "idtoken", "sessiontoken", "privatekey",
        "authorization", "proxyauthorization", "cookie", "setcookie",
    };

    /// <summary>The marker a secret of this kind is replaced with.</summary>
    public static string Marker(string detector) => $"{_markerPrefix}{detector}]";

    /// <summary>
    /// Redacts every secret in a piece of text.
    /// </summary>
    /// <param name="text">The text to scan.</param>
    /// <param name="includePii">Also redact email addresses and card numbers.</param>
    /// <returns>
    /// The text with markers in place of secrets - the same instance when nothing
    /// matched - and which detectors fired.
    /// </returns>
    public static SecretRedaction Redact(string text, bool includePii)
    {
        ArgumentNullException.ThrowIfNull(text);

        List<Finding>? findings = null;

        for (var index = 0; index < _detectors.Length; index++)
        {
            var detector = _detectors[index];

            if (detector.IsPii && !includePii)
            {
                continue;
            }

            foreach (Match match in detector.Pattern.Matches(text))
            {
                // A Match is itself a Group, so the whole match stands in when
                // the pattern names no secret group.
                var secret = match.Groups[_secretGroup];
                var span = secret.Success ? secret : match;

                if (detector.Accept is { } accept && !accept(text, span))
                {
                    continue;
                }

                (findings ??= []).Add(new Finding(span.Index, span.Index + span.Length, index));
            }
        }

        return findings is null
            ? new SecretRedaction(text, SecretReport.Clean)
            : Apply(text, findings);
    }

    /// <summary>
    /// Redacts every secret in a JSON value: string contents, and the whole of
    /// any string stored under a sensitive key.
    /// </summary>
    /// <param name="element">The value to scan.</param>
    /// <param name="propertyName">
    /// The key the value is stored under, when it has one. A tool argument is a
    /// value in a dictionary, so its name arrives here rather than inside the
    /// element.
    /// </param>
    /// <param name="includePii">Also redact email addresses and card numbers.</param>
    /// <returns>A redacted copy, or the original element when nothing matched.</returns>
    /// <remarks>
    /// Only string values are touched. Keys are left alone, and numbers are not
    /// rewritten into marker strings: changing a value's JSON type would break a
    /// schema-checked tool in a way a marker inside a string does not.
    ///
    /// Two passes, and the second only on a hit. Nearly every payload is clean,
    /// and the first pass reads it without a buffer, a writer or a reparse; a hit
    /// pays for scanning its strings twice, which is the rare path.
    /// </remarks>
    public static JsonRedaction RedactJson(JsonElement element, string? propertyName, bool includePii)
    {
        var report = SecretReport.Clean;

        Write(writer: null, element, propertyName, includePii, ref report);

        if (report.IsClean)
        {
            return new JsonRedaction(element, report);
        }

        var buffer = new ArrayBufferWriter<byte>();

        // The second pass finds exactly what the first did, so its report is
        // discarded rather than merged into a double count.
        var rewritten = SecretReport.Clean;

        using (var writer = new Utf8JsonWriter(buffer))
        {
            Write(writer, element, propertyName, includePii, ref rewritten);
        }

        // Clone detaches the element from the document, which is disposed here;
        // the caller may hold the value for as long as the call lasts.
        using var document = JsonDocument.Parse(buffer.WrittenMemory);

        return new JsonRedaction(document.RootElement.Clone(), report);
    }

    /// <summary>
    /// What a human may be shown of one argument value: its secrets replaced,
    /// as text.
    /// </summary>
    /// <param name="value">The argument value.</param>
    /// <param name="propertyName">The argument's name, so a <c>password</c> is redacted whole.</param>
    /// <param name="includePii">Also redact email addresses and card numbers.</param>
    /// <returns>
    /// A string value unquoted, so a path reads as a path; anything else as JSON,
    /// so an object or a number is not misrepresented.
    /// </returns>
    /// <remarks>
    /// The same rules the audit log and the forwarded arguments get - sensitive
    /// field names, decoded strings, PII when configured - so an approver is never
    /// shown a value the log was not allowed to keep. A non-string value is then
    /// scanned once more as text, for what <see cref="RedactJson"/> leaves alone
    /// by design: keys, and a card number sent as a JSON number. Neither changes
    /// a type here, because this text goes to a person rather than to a tool.
    /// </remarks>
    public static string RedactForDisplay(JsonElement value, string? propertyName, bool includePii)
    {
        if (value.ValueKind is JsonValueKind.String)
        {
            var report = SecretReport.Clean;
            return RedactString(value.GetString()!, propertyName, includePii, ref report);
        }

        var json = RedactJson(value, propertyName, includePii).Element.GetRawText();

        return Redact(json, includePii).Text;
    }

    /// <remarks>
    /// One walk for both passes: with no writer it only scans, so the scan the
    /// rewrite depends on cannot drift from the one that decides whether to
    /// rewrite at all.
    /// </remarks>
    private static void Write(
        Utf8JsonWriter? writer,
        JsonElement element,
        string? propertyName,
        bool includePii,
        ref SecretReport report)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer?.WriteStartObject();
                foreach (var property in element.EnumerateObject())
                {
                    writer?.WritePropertyName(property.Name);
                    Write(writer, property.Value, property.Name, includePii, ref report);
                }

                writer?.WriteEndObject();
                break;

            case JsonValueKind.Array:
                // Items inherit the array's key: every entry of "api_keys" or
                // "authorization" is as sensitive as a single one would be.
                writer?.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    Write(writer, item, propertyName, includePii, ref report);
                }

                writer?.WriteEndArray();
                break;

            case JsonValueKind.String:
                var redacted = RedactString(element.GetString()!, propertyName, includePii, ref report);
                writer?.WriteStringValue(redacted);
                break;

            default:
                if (writer is not null)
                {
                    element.WriteTo(writer);
                }

                break;
        }
    }

    private static string RedactString(string value, string? propertyName, bool includePii, ref SecretReport report)
    {
        // The whole value, not just the part a pattern recognises: a password
        // field holding "correct horse battery staple" has no shape to match,
        // and a partial redaction of one would leave the rest of it in the log.
        // Empty is left alone because there is nothing in it to hide.
        if (value.Length > 0 && IsSensitiveField(propertyName))
        {
            report = report.Merge(new SecretReport([SensitiveField], 1));
            return Marker(SensitiveField);
        }

        var redaction = Redact(value, includePii);
        report = report.Merge(redaction.Report);
        return redaction.Text;
    }

    private static bool IsSensitiveField(string? name)
    {
        if (name is null)
        {
            return false;
        }

        var folded = new StringBuilder(name.Length);

        foreach (var value in name)
        {
            if (char.IsLetterOrDigit(value))
            {
                folded.Append(char.ToLowerInvariant(value));
            }
        }

        return _sensitiveFields.Contains(folded.ToString());
    }

    /// <summary>
    /// Replaces findings with markers, merging any that overlap.
    /// </summary>
    /// <remarks>
    /// Overlaps are merged rather than skipped. A bearer header carrying a JWT is
    /// two findings over nearly the same span; skipping the second because it
    /// starts inside the first would be fine, but skipping one that also extends
    /// PAST the first would leave the tail of a secret in the output. Taking the
    /// union of the spans can only ever redact more.
    /// </remarks>
    private static SecretRedaction Apply(string text, List<Finding> findings)
    {
        findings.Sort(static (left, right) => left.Start != right.Start
            ? left.Start.CompareTo(right.Start)
            : left.Detector.CompareTo(right.Detector));

        var builder = new StringBuilder(text.Length);
        var names = new List<string>();
        var count = 0;
        var cursor = 0;
        var index = 0;

        while (index < findings.Count)
        {
            var first = findings[index];
            var end = first.End;

            for (index++; index < findings.Count && findings[index].Start < end; index++)
            {
                end = Math.Max(end, findings[index].End);
            }

            var name = _detectors[first.Detector].Name;

            builder.Append(text, cursor, first.Start - cursor).Append(Marker(name));
            cursor = end;
            count++;

            if (!names.Contains(name))
            {
                names.Add(name);
            }
        }

        builder.Append(text, cursor, text.Length - cursor);

        return new SecretRedaction(builder.ToString(), new SecretReport(names, count));
    }

    private static bool ContainsDigit(string text, Group span) =>
        text.AsSpan(span.Index, span.Length).IndexOfAnyInRange('0', '9') >= 0;

    /// <summary>
    /// A quoted value is taken at its word. A bare one must look generated, and
    /// must not be the start of an expression.
    /// </summary>
    /// <remarks>
    /// Source code is full of <c>password = get_password()</c> and
    /// <c>api_key = os.environ["KEY"]</c>. Redacting those would put markers in
    /// the middle of a file the agent is editing, and the next write would save
    /// them. A bare value followed by a call or an index is code; one with no
    /// digit and no symbol in it is far more likely a name than a secret.
    /// </remarks>
    private static bool IsCredentialValue(string text, Group span)
    {
        // Our own marker, from an earlier pass. Without this, re-scanning
        // redacted JSON relabels "password": "[REDACTED:sensitive-field]" as a
        // credential assignment, and the reader loses the more specific name.
        if (text.AsSpan(span.Index, span.Length).StartsWith(_markerPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        if (text[span.Index - 1] is '"' or '\'')
        {
            return true;
        }

        var end = span.Index + span.Length;

        if (end < text.Length && text[end] is '(' or '[')
        {
            return false;
        }

        return text.AsSpan(span.Index, span.Length).IndexOfAny("0123456789!@#$%^*+/=~") >= 0;
    }

    /// <summary>
    /// A known card prefix and a valid Luhn check digit.
    /// </summary>
    /// <remarks>
    /// Thirteen to nineteen digits is also an order number, a millisecond
    /// timestamp or a phone number with its country code, and a tenth of all
    /// random digit strings pass Luhn. The prefix check is what removes the
    /// common false positive: a millisecond timestamp from this century starts
    /// with 1, which no card network issues.
    /// </remarks>
    private static bool IsCardNumber(string text, Group span)
    {
        // The pattern allows at most nineteen digits, so the buffer cannot
        // overflow.
        Span<char> digits = stackalloc char[19];
        var length = 0;

        foreach (var value in text.AsSpan(span.Index, span.Length))
        {
            if (char.IsAsciiDigit(value))
            {
                digits[length++] = value;
            }
        }

        digits = digits[..length];

        var knownPrefix = digits[0] switch
        {
            '3' or '4' or '5' or '6' => true,
            // Mastercard's 2221-2720 range, approximated by its second digit.
            '2' => digits[1] is >= '2' and <= '7',
            _ => false,
        };

        return knownPrefix && PassesLuhn(digits);
    }

    private static bool PassesLuhn(ReadOnlySpan<char> digits)
    {
        var sum = 0;
        var doubled = false;

        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var digit = digits[i] - '0';

            if (doubled)
            {
                digit *= 2;

                if (digit > 9)
                {
                    digit -= 9;
                }
            }

            sum += digit;
            doubled = !doubled;
        }

        return sum % 10 == 0;
    }

    private readonly record struct Finding(int Start, int End, int Detector);
}

/// <summary>
/// Redacted text and what was found in it.
/// </summary>
/// <param name="Text">The text with markers in place of secrets.</param>
/// <param name="Report">Which detectors fired, and how often.</param>
public sealed record SecretRedaction(string Text, SecretReport Report);

/// <summary>
/// A redacted JSON value and what was found in it.
/// </summary>
/// <param name="Element">The redacted copy, or the original when nothing matched.</param>
/// <param name="Report">Which detectors fired, and how often.</param>
public sealed record JsonRedaction(JsonElement Element, SecretReport Report);

/// <summary>
/// What a secret scan found.
/// </summary>
/// <param name="Detectors">
/// Names of the detectors that fired, in the order first seen, without
/// duplicates.
/// </param>
/// <param name="Count">How many values were redacted in total.</param>
/// <remarks>
/// Names and a count, never the values. That is the entire point of the
/// component: a report that quoted the secret it found would carry it straight
/// into the audit log it was meant to be kept out of.
/// </remarks>
public sealed record SecretReport(IReadOnlyList<string> Detectors, int Count)
{
    /// <summary>Nothing matched.</summary>
    public static SecretReport Clean { get; } = new([], 0);

    /// <summary>True when nothing was redacted.</summary>
    public bool IsClean => Count == 0;

    /// <summary>The detector names as a comma-separated list.</summary>
    public string Summary => string.Join(", ", Detectors);

    /// <summary>Combines two reports, keeping the order of the first.</summary>
    public SecretReport Merge(SecretReport other)
    {
        ArgumentNullException.ThrowIfNull(other);

        if (other.IsClean)
        {
            return this;
        }

        if (IsClean)
        {
            return other;
        }

        return new SecretReport(ResultContent.OrderedUnion(Detectors, other.Detectors), Count + other.Count);
    }
}
