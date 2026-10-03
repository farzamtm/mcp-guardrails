using System.Text.Json;
using McpGuardrails.Core.Policy;

namespace McpGuardrails.Core.Tests.Policy;

public sealed class ArgumentPredicateTests
{
    private static readonly IReadOnlyDictionary<string, JsonElement> _arguments =
        TestArguments.From("""
            {
              "limit": 500,
              "path": "/etc/passwd",
              "dry_run": false,
              "nothing": null,
              "mode": "force",
              "options": { "recursive": true },
              "tags": ["a", "b"]
            }
            """);

    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement.Clone();

    /// <summary>
    /// The outcome name, so these tests read as a table of input to outcome.
    /// </summary>
    private static string Outcome(
        ArgumentPredicate predicate,
        IReadOnlyDictionary<string, JsonElement>? arguments) =>
        predicate.Evaluate(arguments).ToString();

    private static bool Evaluate(ArgumentPredicate predicate) =>
        Outcome(predicate, _arguments) == "Satisfied";

    // ------------------------------------------------------------------- eq

    [Theory]
    [InlineData("$.limit", "500", true)]
    [InlineData("$.limit", "500.0", true)]
    [InlineData("$.limit", "499", false)]
    [InlineData("$.path", "\"/etc/passwd\"", true)]
    [InlineData("$.path", "\"/etc/shadow\"", false)]
    [InlineData("$.dry_run", "false", true)]
    [InlineData("$.dry_run", "true", false)]
    [InlineData("$.options.recursive", "true", true)]
    [InlineData("$.nothing", "null", true)]
    // Mismatched kinds are never equal: "500" the string is not 500 the number,
    // which is why the YAML loader preserves quoting.
    [InlineData("$.limit", "\"500\"", false)]
    [InlineData("$.path", "500", false)]
    [InlineData("$.nothing", "false", false)]
    // Structures are compared by path, not deeply.
    [InlineData("$.options", "{\"recursive\": true}", false)]
    [InlineData("$.tags", "[\"a\", \"b\"]", false)]
    public void Eq_ComparesByKindAndValue(string path, string expected, bool matches) =>
        Assert.Equal(matches, Evaluate(new ArgumentPredicate { Path = path, Eq = Json(expected) }));

    // ---------------------------------------------------------------- gt / lt

    [Theory]
    [InlineData(100, true)]
    [InlineData(500, false)]
    [InlineData(900, false)]
    public void Gt_ComparesNumerically(double bound, bool matches) =>
        Assert.Equal(matches, Evaluate(new ArgumentPredicate { Path = "$.limit", Gt = bound }));

    [Theory]
    [InlineData(900, true)]
    [InlineData(500, false)]
    [InlineData(100, false)]
    public void Lt_ComparesNumerically(double bound, bool matches) =>
        Assert.Equal(matches, Evaluate(new ArgumentPredicate { Path = "$.limit", Lt = bound }));

    [Fact]
    public void NumericOperators_DoNotMatchNonNumbers()
    {
        // A string that looks like a number is still a string. Coercing here
        // would make "limit: '1000'" quietly bypass a gt rule.
        Assert.False(Evaluate(new ArgumentPredicate { Path = "$.path", Gt = 1 }));
        Assert.False(Evaluate(new ArgumentPredicate { Path = "$.path", Lt = 1 }));
    }

    // ---------------------------------------------------------------- strings

    [Theory]
    [InlineData("^/etc/", true)]
    [InlineData("passwd$", true)]
    [InlineData("^/home/", false)]
    public void Matches_AppliesTheRegexToStringValues(string pattern, bool expected) =>
        Assert.Equal(expected, Evaluate(new ArgumentPredicate { Path = "$.path", Matches = pattern }));

    [Fact]
    public void Matches_DoesNotMatchNonStrings() =>
        Assert.False(Evaluate(new ArgumentPredicate { Path = "$.limit", Matches = "500" }));

    [Theory]
    [InlineData("/etc", true)]
    [InlineData("/etc/passwd", true)]
    [InlineData("/home", false)]
    public void Prefix_IsAnOrdinalStartsWith(string prefix, bool expected) =>
        Assert.Equal(expected, Evaluate(new ArgumentPredicate { Path = "$.path", Prefix = prefix }));

    [Fact]
    public void Prefix_DoesNotMatchNonStrings() =>
        Assert.False(Evaluate(new ArgumentPredicate { Path = "$.limit", Prefix = "5" }));

    [Theory]
    [InlineData("/workspace/", true)]
    [InlineData("/etc/", false)]
    public void NotPrefix_MatchesAStringThatDoesNotStartWithIt(string prefix, bool expected) =>
        Assert.Equal(expected, Evaluate(new ArgumentPredicate { Path = "$.path", NotPrefix = prefix }));

    [Theory]
    [InlineData("$.limit")]
    [InlineData("$.tags")]
    [InlineData("$.options")]
    [InlineData("$.nothing")]
    [InlineData("$.dry_run")]
    public void NotPrefix_MatchesAPresentNonString(string path)
    {
        // Fail closed: a value that is not a string cannot be shown to start
        // with the prefix, so a deny rule built on not_prefix must still fire.
        // Otherwise {"path": ["/etc/passwd"]} walks past it to a server that may
        // happily take the first element.
        Assert.True(Evaluate(new ArgumentPredicate { Path = path, NotPrefix = "/workspace/" }));
    }

    [Fact]
    public void NotPrefix_MatchesAnArrayWhoseElementWouldPass()
    {
        // Even an array holding an allowed path is not an allowed string: the
        // operator judges the value the server receives, not a guess at how the
        // server will unwrap it.
        var arguments = TestArguments.From("""{"path": ["/workspace/notes.txt"]}""");

        Assert.Equal(
            "Satisfied",
            Outcome(new ArgumentPredicate { Path = "$.path", NotPrefix = "/workspace/" }, arguments));
    }

    [Theory]
    [InlineData("9007199254740993", "9007199254740992", false)]
    [InlineData("9007199254740993", "9007199254740993", true)]
    [InlineData("-9223372036854775808", "-9223372036854775807", false)]
    [InlineData("1", "1.0", true)]
    [InlineData("1", "1e0", true)]
    [InlineData("0.1", "0.10", true)]
    [InlineData("0.1", "0.2", false)]
    [InlineData("1e400", "1e400", true)]
    [InlineData("5", "1e400", false)]
    [InlineData("1e400", "5", false)]
    public void Eq_ComparesNumbersExactly(string actual, string expected, bool matches)
    {
        // Through a double, integers above 2^53 collide: an eq or in rule keyed
        // on an id would fire on its neighbour. Numerically equal spellings must
        // still agree, and magnitudes past decimal's range must not throw.
        var arguments = TestArguments.From($$"""{"n": {{actual}}}""");

        Assert.Equal(
            matches ? "Satisfied" : "NotSatisfied",
            Outcome(new ArgumentPredicate { Path = "$.n", Eq = Json(expected) }, arguments));
    }

    // --------------------------------------------------------------------- in

    [Fact]
    public void In_MatchesAnyListedValue()
    {
        var predicate = new ArgumentPredicate
        {
            Path = "$.mode",
            In = [Json("\"force\""), Json("\"purge\"")],
        };

        Assert.True(Evaluate(predicate));
    }

    [Fact]
    public void In_DoesNotMatchWhenNothingLinesUp()
    {
        var predicate = new ArgumentPredicate
        {
            Path = "$.mode",
            In = [Json("\"safe\""), Json("42")],
        };

        Assert.False(Evaluate(predicate));
    }

    [Fact]
    public void In_DoesNotConfuseLargeIntegers()
    {
        var predicate = new ArgumentPredicate
        {
            Path = "$.id",
            In = [Json("9007199254740992")],
        };

        Assert.Equal(
            "NotSatisfied",
            Outcome(predicate, TestArguments.From("""{"id": 9007199254740993}""")));
    }

    // -------------------------------------------------------- absent arguments

    [Theory]
    [InlineData("$.missing")]
    [InlineData("$.options.missing")]
    public void AnAbsentArgument_SatisfiesNoPredicate(string path)
    {
        // The rule this pins down: not_prefix asserts "there is a value and it
        // does not start with this", NOT "no value starts with this". A rule must
        // not fire on evidence that was never supplied.
        Assert.False(Evaluate(new ArgumentPredicate { Path = path, NotPrefix = "/workspace/" }));
        Assert.False(Evaluate(new ArgumentPredicate { Path = path, Prefix = "/etc/" }));
        Assert.False(Evaluate(new ArgumentPredicate { Path = path, Eq = Json("null") }));
        Assert.False(Evaluate(new ArgumentPredicate { Path = path, Gt = 0 }));
    }

    [Fact]
    public void NoArgumentsAtAll_SatisfiesNoPredicate() =>
        Assert.Equal(
            "NotSatisfied",
            Outcome(new ArgumentPredicate { Path = "$.limit", Gt = 1 }, null));

    // ------------------------------------------------------------------ ReDoS

    [Fact]
    public void ACatastrophicPatternTimesOutAndIsUndecidable()
    {
        // Policy files are configuration and configuration must not be able to
        // hang the proxy, so evaluation is abandoned after RegexTimeout. What it
        // must NOT do is report "no match": the model chooses the argument and
        // its length, so a bounded-but-silent give-up is a bypass it can trigger
        // on demand. Indeterminate carries "undecided" up to the evaluator, which
        // refuses the call. See PolicyEvaluatorTests for the other half.
        var arguments = TestArguments.From($$"""{ "path": "{{new string('a', 40)}}!" }""");

        var predicate = new ArgumentPredicate { Path = "$.path", Matches = "^(a+)+$" };

        Assert.Equal("Indeterminate", Outcome(predicate, arguments));
    }

    [Fact]
    public void ATimeoutOnANonStringValue_IsNotEvenAttempted() =>
        // Kind is checked before the pattern runs, so a non-string can never be
        // the thing that exhausts the budget.
        Assert.Equal(
            "NotSatisfied",
            Outcome(new ArgumentPredicate { Path = "$.limit", Matches = "^(a+)+$" }, _arguments));

    // -------------------------------------------------------------- validation

    [Theory]
    [InlineData(null, "without a 'path'")]
    [InlineData("   ", "without a 'path'")]
    public void Validate_RequiresAPath(string? path, string expectedFragment)
    {
        var predicate = new ArgumentPredicate { Path = path, Gt = 1 };

        var exception = Assert.Throws<PolicyException>(() => predicate.Validate("r"));
        Assert.Contains(expectedFragment, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_RejectsAnUnsupportedPath()
    {
        var predicate = new ArgumentPredicate { Path = "$.items[*]", Gt = 1 };

        var exception = Assert.Throws<PolicyException>(() => predicate.Validate("r"));
        Assert.Contains("unsupported argument path", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_RejectsAPredicateWithNoOperator()
    {
        var exception = Assert.Throws<PolicyException>(
            () => new ArgumentPredicate { Path = "$.limit" }.Validate("r"));

        Assert.Contains("no operator", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_RejectsMoreThanOneOperator()
    {
        // Two conditions on one value is two list entries. Silently honouring the
        // first would make the other one a comment.
        var predicate = new ArgumentPredicate { Path = "$.limit", Gt = 1, Lt = 10 };

        var exception = Assert.Throws<PolicyException>(() => predicate.Validate("r"));
        Assert.Contains("more than one", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_RejectsAnEmptyInList()
    {
        var predicate = new ArgumentPredicate { Path = "$.mode", In = [] };

        var exception = Assert.Throws<PolicyException>(() => predicate.Validate("r"));
        Assert.Contains("empty 'in' list", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_RejectsAnEmptyPrefix()
    {
        // Always true, so the rule reduces to "the argument is a string" - a
        // guardrail the operator believes in and does not have.
        var predicate = new ArgumentPredicate { Path = "$.path", Prefix = "" };

        var exception = Assert.Throws<PolicyException>(() => predicate.Validate("r"));
        Assert.Contains("empty 'prefix'", exception.Message, StringComparison.Ordinal);
        Assert.Contains("every string value", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_RejectsAnEmptyNotPrefix()
    {
        // Never true, so the rule can never fire.
        var predicate = new ArgumentPredicate { Path = "$.path", NotPrefix = "" };

        var exception = Assert.Throws<PolicyException>(() => predicate.Validate("r"));
        Assert.Contains("empty 'not_prefix'", exception.Message, StringComparison.Ordinal);
        Assert.Contains("never match", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_ExplainsThatANullValueIsNotAnOperator()
    {
        // 'eq: null' deserialises to an absent operator, so the message has to
        // name that specifically or it describes the wrong mistake.
        var exception = Assert.Throws<PolicyException>(
            () => new ArgumentPredicate { Path = "$.limit", Eq = null }.Validate("r"));

        Assert.Contains("eq: null", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnvalidatedPredicate_FailsAsAConfigurationErrorRatherThanACrash()
    {
        // PolicyLoader always validates, but PolicyDocument and PolicyRule are
        // public: a predicate built in code reaches Evaluate without ever having
        // been checked. It must not dereference its way into a NullReferenceException.
        var predicate = new ArgumentPredicate { Path = "$.limit" };

        var exception = Assert.Throws<PolicyException>(() => predicate.Evaluate(_arguments));
        Assert.Contains("no operator", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AValidatedPredicate_ResolvesItsOperatorOnlyOnce()
    {
        // The resolved form is cached, so a policy's patterns are compiled once
        // at load instead of being fetched from the small, process-global Regex
        // cache on every call.
        var predicate = new ArgumentPredicate { Path = "$.path", Matches = "^/etc/" };

        predicate.Validate("r");

        Assert.Equal("Satisfied", Outcome(predicate, _arguments));
        Assert.Equal("Satisfied", Outcome(predicate, _arguments));
    }

    [Fact]
    public void Validate_RejectsAnInvalidRegex()
    {
        // Caught at load, not on the first tool call: a policy typo must not
        // surface as a failed tool call hours into a session.
        var predicate = new ArgumentPredicate { Path = "$.path", Matches = "([unclosed" };

        var exception = Assert.Throws<PolicyException>(() => predicate.Validate("r"));
        Assert.Contains("invalid regular expression", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("$.limit")]
    [InlineData("$['content-type']")]
    public void Validate_AcceptsAWellFormedPredicate(string path) =>
        new ArgumentPredicate { Path = path, Eq = Json("1") }.Validate("r");

    [Fact]
    public void Validate_AcceptsAValidRegex() =>
        new ArgumentPredicate { Path = "$.path", Matches = "^/etc/" }.Validate("r");
}
