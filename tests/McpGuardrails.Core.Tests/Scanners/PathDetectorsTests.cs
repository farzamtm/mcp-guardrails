using McpGuardrails.Core.Scanners;

namespace McpGuardrails.Core.Tests.Scanners;

/// <summary>
/// The sensitive-path and path-traversal detectors: credential locations and
/// <c>..</c> in every encoding, against workspace paths and prose that must
/// stay quiet.
/// </summary>
public sealed class PathDetectorsTests
{
    [Theory]
    [InlineData("/home/u/.ssh/id_rsa")]
    [InlineData("~/.ssh/config")]
    [InlineData("/home/u/.ssh")]
    [InlineData("id_rsa")]
    [InlineData("keys/id_ed25519")]
    [InlineData("/Users/u/.aws/credentials")]
    [InlineData("C:\\Users\\u\\.aws\\credentials")]
    [InlineData("~/.config/gcloud/application_default_credentials.json")]
    [InlineData("/root/.kube/config")]
    [InlineData("~/.docker/config.json")]
    [InlineData("~/.npmrc")]
    [InlineData("~/.pypirc")]
    [InlineData("~/.netrc")]
    [InlineData("C:\\Users\\u\\_netrc")]
    [InlineData("~/.git-credentials")]
    [InlineData("~/.pgpass")]
    [InlineData("project/.env")]
    [InlineData(".env")]
    [InlineData("project/.env.local")]
    [InlineData("project/.env.production")]
    [InlineData("/etc/shadow")]
    [InlineData("/etc/gshadow")]
    [InlineData("/etc/sudoers")]
    [InlineData("/etc/sudoers.d/admins")]
    [InlineData("/Users/u/Library/Keychains/login.keychain-db")]
    [InlineData("C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Credentials\\ABC")]
    [InlineData("C:\\Users\\u\\AppData\\Local\\Microsoft\\Credentials\\ABC")]
    [InlineData("~/.mozilla/firefox/abc.default/logins.json")]
    [InlineData("profile/key4.db")]
    [InlineData("profile/key3.db")]
    [InlineData("profile/cookies.sqlite")]
    [InlineData("profile/signons.sqlite")]
    [InlineData("~/.config/google-chrome/Default/Cookies")]
    // Case, encodings and look-alike separators.
    [InlineData("/HOME/U/.SSH/ID_RSA")]
    [InlineData("%2fetc%2fshadow")]
    [InlineData("/home/u/%2essh/id_rsa")]
    [InlineData("／etc／shadow")]
    [InlineData("file:///home/u/.ssh/id_rsa")]
    // Inside a command line: a word with a separator is read as a path.
    [InlineData("cat ~/.ssh/id_rsa")]
    [InlineData("tar czf out.tgz \"/etc/shadow\"")]
    // Paths the file system resolves to a credential file: '.' and '..'
    // segments, and the Windows trailing dots, spaces and default stream.
    [InlineData("/etc/./shadow")]
    [InlineData("/home/u/.aws/./credentials")]
    [InlineData("~/.kube/./config")]
    [InlineData("/home/u/.docker/./config.json")]
    [InlineData("C:\\Users\\u\\AppData\\.\\Roaming\\Microsoft\\Credentials\\x")]
    [InlineData("/etc/x/../shadow")]
    [InlineData("/home/u/.aws/a/b/../../credentials")]
    [InlineData("C:\\Users\\u\\.ssh.\\id_ed25519.")]
    [InlineData("C:\\p\\id_rsa.")]
    [InlineData("C:\\p\\.env::$DATA")]
    [InlineData("C:\\p\\.ENV::$data")]
    [InlineData("C:\\p\\.npmrc...")]
    [InlineData("C:\\p\\.env.local.")]
    // Escapes decoded the way traversal decodes them: double, overlong, IIS.
    [InlineData("%252essh/id_rsa")]
    [InlineData("/home/u/%c0%aessh/id_rsa")]
    [InlineData("/home/u/%u002essh/id_rsa")]
    public void SensitivePath_FiresOnCredentialLocations(string value) =>
        Assert.True(PathDetectors.IsSensitivePath(value, pathNamed: false));

    [Theory]
    [InlineData("src/app/main.cs")]
    [InlineData("/home/u/project/README.md")]
    [InlineData("docs/aws-credentials-guide.md")]
    [InlineData("config/.env.example")]
    [InlineData("config/.env.sample")]
    [InlineData("config/.env.template")]
    [InlineData("id_rsa.pub")]
    [InlineData("keys/id_ed25519.pub")]
    [InlineData("/etc/hosts")]
    [InlineData("shadow")]
    [InlineData("credentials")]
    [InlineData("cookies")]
    [InlineData("recipes/cookies")]
    [InlineData(".aws")]
    [InlineData("")]
    [InlineData("/")]
    [InlineData("./x/./y")]
    [InlineData("../shadow")]
    [InlineData("a/../credentials")]
    [InlineData("/./")]
    [InlineData(".../x")]
    [InlineData("C:\\p\\notes.txt.")]
    // Prose that mentions credential files without a path-like word.
    [InlineData("remember to add .env to .gitignore")]
    [InlineData("the id_rsa key should never be committed")]
    [InlineData("rotate the .npmrc token, then redeploy")]
    public void SensitivePath_StaysQuietOnOrdinaryValues(string value) =>
        Assert.False(PathDetectors.IsSensitivePath(value, pathNamed: false));

    [Fact]
    public void SensitivePath_ReadsAPathNamedArgument_AsOnePath()
    {
        // Spaces would otherwise make it prose, split into words, none with a
        // separator next to the file name.
        const string value = "My Keys/id_rsa";

        Assert.True(PathDetectors.IsSensitivePath(value, pathNamed: true));
        Assert.True(PathDetectors.IsSensitivePath(".env", pathNamed: true));
        Assert.True(PathDetectors.IsSensitivePath(
            "~/Library/Application Support/Google/Chrome/Default/Login Data", pathNamed: true));
        Assert.True(PathDetectors.IsSensitivePath("~/.config/chromium/Default/Web Data", pathNamed: true));
        Assert.False(PathDetectors.IsSensitivePath("add .env to .gitignore", pathNamed: false));
    }

    [Fact]
    public void SensitivePath_ReadsAQuotedWordOfACommand_AsOnePath()
    {
        // A shell keeps a quoted path together, spaces and all; prose is still
        // read word by word, where no single word holds the file name.
        const string copy = "cp \"~/Library/Application Support/Google/Chrome/Default/Login Data\" /tmp/x";

        Assert.True(PathDetectors.IsSensitivePath(copy, pathNamed: false, command: true));
        Assert.False(PathDetectors.IsSensitivePath(copy, pathNamed: false));
        Assert.True(PathDetectors.IsSensitivePath("cp 'My Keys/Login Data' out", pathNamed: false, command: true));
        Assert.True(PathDetectors.IsSensitivePath("cp \"My Keys/Login Data", pathNamed: false, command: true));
        Assert.True(PathDetectors.IsSensitivePath("cp x\"My Keys/Login Data\" out", pathNamed: false, command: true));
        Assert.False(PathDetectors.IsSensitivePath("echo 'hello world' a/b", pathNamed: false, command: true));
        Assert.False(PathDetectors.IsSensitivePath("ls -la 'a b'/c  ", pathNamed: false, command: true));
    }

    [Fact]
    public void SensitivePath_AnyWhitespace_MakesAValueProse()
    {
        // An em space or an ideographic space separates words just as a space
        // does, so the value is read word by word rather than as one path.
        Assert.True(PathDetectors.IsSensitivePath("cat\u2003~/.ssh/id_rsa", pathNamed: false));
        Assert.False(PathDetectors.IsSensitivePath("add\u2003.env\u1680to\u3000.gitignore", pathNamed: false));
    }

    [Theory]
    [InlineData("../etc/passwd")]
    [InlineData("a/../b")]
    [InlineData("a/..")]
    [InlineData("..\\windows\\win.ini")]
    [InlineData("a\\..\\b")]
    [InlineData("see ../README.md")]
    [InlineData("path=../secret")]
    [InlineData("%2e%2e%2fetc%2fpasswd")]
    [InlineData("%2E%2E%2F")]
    [InlineData("..%2f")]
    [InlineData("..%5c")]
    [InlineData("%252e%252e%252f")]
    [InlineData("..%252f")]
    [InlineData("..%255c")]
    [InlineData("%c0%ae%c0%ae%c0%af")]
    [InlineData("..%c1%9c")]
    [InlineData("%e0%80%ae%e0%80%ae%e0%80%af")]
    [InlineData("%u002e%u002e%u002f")]
    [InlineData("..%u005c")]
    [InlineData("..%u2215")]
    [InlineData("．．/x")]
    [InlineData("․․/x")]
    [InlineData("..∕x")]
    [InlineData("..⁄x")]
    [InlineData("..／x")]
    [InlineData("..＼x")]
    [InlineData("..⧵x")]
    [InlineData("%25252e%25252e%25252f")]
    [InlineData("%2e%2E%5C")]
    public void Traversal_FiresOnDotDotSegments(string value) => Assert.True(PathDetectors.HasTraversal(value));

    [Theory]
    [InlineData("")]
    [InlineData("..")]
    [InlineData("wait..")]
    [InlineData("hmm.. ok")]
    [InlineData("...")]
    [InlineData(".../x")]
    [InlineData("./x")]
    [InlineData("a/.b/c")]
    [InlineData("a/b..c/d")]
    [InlineData("v1..v2")]
    [InlineData("100%")]
    [InlineData("%41%42")]
    [InlineData("50% off")]
    // Word breaks end a segment, so ".." glued to punctuation is not a path.
    [InlineData("x=..")]
    [InlineData("(..)")]
    [InlineData("[..]")]
    [InlineData("{..}")]
    [InlineData("<..>")]
    [InlineData("a|..|b")]
    [InlineData("a&..&b")]
    [InlineData("a,..,b")]
    [InlineData("a;..;b")]
    [InlineData("\"..\"")]
    [InlineData("'..'")]
    [InlineData("`..`")]
    public void Traversal_StaysQuietOnOrdinaryValues(string value) => Assert.False(PathDetectors.HasTraversal(value));

    [Fact]
    public void LongValues_AreScannedInLinearTime()
    {
        // Sized so a quadratic scan would take minutes while a linear one takes
        // well under a second, even under coverage instrumentation on a busy
        // CI runner: the bound below separates the two without being a
        // benchmark.
        var segments = string.Concat(Enumerable.Repeat("a/", 200_000));
        var percents = string.Concat(Enumerable.Repeat("%c0%", 200_000));
        var words = string.Concat(Enumerable.Repeat("x/y ", 200_000));

        var started = System.Diagnostics.Stopwatch.StartNew();
        Assert.False(PathDetectors.IsSensitivePath(segments, pathNamed: false));
        Assert.False(PathDetectors.IsSensitivePath(words, pathNamed: false));
        Assert.False(PathDetectors.HasTraversal(segments));
        Assert.False(PathDetectors.HasTraversal(percents));
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(10), $"took {started.Elapsed}");
    }
}
