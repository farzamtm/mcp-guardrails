using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Policy;

/// <summary>
/// Covers the YAML-to-JSON scalar conversion and the loader's failure paths.
/// </summary>
/// <remarks>
/// The scalar typing rules are exercised through extra keys that the policy
/// schema ignores. That is deliberate: the conversion runs over the whole
/// document regardless of schema, and step 6 will introduce real boolean and
/// numeric fields (annotation matching, JSONPath comparisons) that depend on
/// these branches being right.
/// </remarks>
public sealed class PolicyLoaderScalarTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), $"guardrails-scalar-{Guid.NewGuid():N}");

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Theory]
    [InlineData("flag: true")]
    [InlineData("flag: True")]
    [InlineData("flag: TRUE")]
    [InlineData("flag: false")]
    [InlineData("flag: False")]
    [InlineData("flag: FALSE")]
    [InlineData("count: 42")]
    [InlineData("count: -7")]
    [InlineData("ratio: 1.5")]
    [InlineData("ratio: -0.25")]
    [InlineData("nothing: ~")]
    [InlineData("nothing: null")]
    [InlineData("nothing: Null")]
    [InlineData("nothing: NULL")]
    [InlineData("nothing:")]
    [InlineData("text: hello")]
    public void Parse_ConvertsEveryScalarShapeWithoutFailing(string extra)
    {
        var policy = PolicyLoader.Parse($"""
            {extra}
            rules:
              - name: r
                decision: deny
            """);

        Assert.Equal("r", Assert.Single(policy.EffectiveRules).Name);
    }

    [Fact]
    public void Parse_HandlesNestedSequencesAndMappings()
    {
        // Exercises the array and nested-object conversion paths.
        var policy = PolicyLoader.Parse("""
            metadata:
              owners:
                - alice
                - bob
              nested:
                deep:
                  value: 1
            rules:
              - name: r
                decision: deny
            """);

        Assert.Single(policy.EffectiveRules);
    }

    [Fact]
    public void Parse_RejectsNonStringMappingKeys()
    {
        // A YAML complex key (`? [a, b]`) has no JSON equivalent.
        var exception = Assert.Throws<PolicyException>(() => PolicyLoader.Parse("""
            ? [a, b]
            : value
            """));

        Assert.Contains("keys must be plain strings", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Regression test for a fail-open bug.
    /// </summary>
    /// <remarks>
    /// File.Exists() returns false for a directory, so a policy path pointing at
    /// one fell through to "no file, therefore no policy" and allowed everything.
    /// A misconfigured path must be loud, not permissive.
    /// </remarks>
    [Fact]
    public void LoadFromFileOrEmpty_RejectsADirectoryInsteadOfFailingOpen()
    {
        Directory.CreateDirectory(_directory);

        var exception = Assert.Throws<PolicyException>(
            () => PolicyLoader.LoadFromFileOrEmpty(_directory));

        Assert.Contains("is a directory", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LoadFromFileOrEmpty_ReportsAnUnreadableFileAsAPolicyError()
    {
        // Permission bits are a Unix concept; chmod is a no-op on Windows and
        // root ignores them, so verify the file is genuinely unreadable before
        // asserting rather than silently testing nothing.
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "unreadable.yaml");
        File.WriteAllText(path, "rules: []");
        File.SetUnixFileMode(path, UnixFileMode.None);

        try
        {
            File.ReadAllText(path);
            return; // running as root; the permission bits do not apply
        }
        catch (Exception)
        {
            // Expected: the file really is unreadable, so the assertion is meaningful.
        }

        var exception = Assert.Throws<PolicyException>(
            () => PolicyLoader.LoadFromFileOrEmpty(path));

        Assert.Contains("Could not read", exception.Message, StringComparison.Ordinal);

        // Restore so the directory can be cleaned up.
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    [Fact]
    public void Parse_TreatsAnEmptyQuotedStringAsAString()
    {
        var policy = PolicyLoader.Parse("""
            note: ""
            rules:
              - name: r
                decision: deny
            """);

        Assert.Single(policy.EffectiveRules);
    }
}

/// <summary>
/// Direct tests for evaluator helpers whose defensive branches are unreachable
/// through the public API.
/// </summary>
/// <remarks>
/// The constructor rejects undefined verdicts, so these arms cannot be reached
/// by evaluating a policy. They are still required by the compiler, and untested
/// branches in a security component are worth closing rather than excusing.
/// </remarks>
public sealed class PolicyEvaluatorFallbackTests
{
    [Theory]
    [InlineData(Verdict.Allow, "allow")]
    [InlineData(Verdict.Deny, "deny")]
    [InlineData(Verdict.RequireApproval, "require_approval")]
    public void Describe_UsesTheWireSpelling(Verdict verdict, string expected)
    {
        Assert.Equal(expected, PolicyEvaluator.Describe(verdict));
    }

    [Fact]
    public void Describe_FallsBackForAnUndefinedVerdict()
    {
        Assert.Equal("99", PolicyEvaluator.Describe((Verdict)99));
    }

    [Fact]
    public void DefaultMessage_FallsBackForAnUndefinedVerdict()
    {
        var rule = new PolicyRule { Name = "odd", Decision = (Verdict)99 };

        Assert.Equal("Rule 'odd' applied.", PolicyEvaluator.DefaultMessage(rule));
    }
}
