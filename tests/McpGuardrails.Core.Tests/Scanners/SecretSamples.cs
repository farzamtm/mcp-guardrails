namespace McpGuardrails.Core.Tests.Scanners;

/// <summary>
/// Fake credentials, in the shapes the detectors look for.
/// </summary>
/// <remarks>
/// Every sample is assembled by concatenation so that no complete token appears
/// as a literal anywhere in the repository. GitHub push protection and every
/// other secret scanner downstream of this repository match on source text; a
/// test fixture that looked like a real key would be flagged, or worse, teach
/// people to dismiss the flag. None of these values were ever valid.
/// </remarks>
internal static class SecretSamples
{
    public static readonly string AwsAccessKey = "AKIA" + "IOSFODNN7EXAMPLE";

    public static readonly string GitHubToken = "ghp" + "_" + new string('a', 30) + "123456";

    public static readonly string GitHubFineGrained = "github" + "_pat_" + new string('B', 20) + "_c4";

    public static readonly string SlackToken = "xoxb" + "-1234567890-abcdefghij";

    public static readonly string SlackWebhook =
        "https://hooks.slack.com/" + "services/T0000/B0000/" + new string('x', 24);

    public static readonly string StripeKey = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc";

    public static readonly string AnthropicKey = "sk" + "-ant-" + "api03-" + new string('Z', 24);

    public static readonly string OpenAiKey = "sk" + "-proj-" + "abc123" + new string('Q', 20);

    public static readonly string GoogleApiKey = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvW";

    public static readonly string Jwt =
        "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0" + ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

    public static readonly string PrivateKeyBody =
        "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n" +
        "VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK\n";

    public static readonly string PrivateKey =
        "-----BEGIN " + "RSA PRIVATE KEY-----\n" + PrivateKeyBody + "-----END " + "RSA PRIVATE KEY-----";

    /// <summary>The Visa test number every payment provider documents.</summary>
    public static readonly string CardNumber = "4111" + " 1111 1111 1111";
}
