using System.Text.Json;
using System.Text.Json.Nodes;
using McpGuardrails.Core.Access;
using McpGuardrails.Core.Packs;
using McpGuardrails.Core.Scanners;
using McpGuardrails.Core.Serialization;
using McpGuardrails.Core.Upstream;

namespace McpGuardrails.Core.Policy;

/// <summary>The outcome of one test case.</summary>
/// <param name="Label">How the case is named in output: its name, else its number and call.</param>
/// <param name="Passed">True when the decision matched every expectation.</param>
/// <param name="Failure">What differed, when it failed.</param>
/// <param name="Trail">The decision trail, when it failed; the same text as <c>--explain</c>.</param>
public sealed record PolicyTestCaseResult(
    string Label,
    bool Passed,
    string? Failure,
    IReadOnlyList<string> Trail);

/// <summary>Every case of one test file.</summary>
public sealed record PolicyTestReport(IReadOnlyList<PolicyTestCaseResult> Cases)
{
    /// <summary>The cases that failed.</summary>
    public IReadOnlyList<PolicyTestCaseResult> Failures => [.. Cases.Where(c => !c.Passed)];
}

/// <summary>Runs a <c>policy test</c> file against the real evaluator.</summary>
/// <remarks>
/// The decisions come from <see cref="PolicyEvaluator"/> itself, not a model of
/// it, with facts built the way the proxy builds them: an advertised tool has
/// its server and hints, an unknown one has neither. No server is spawned, so
/// a test runs in CI with no network, keys or Node.
///
/// The policy decision is tested, followed by the two scanners that can change
/// it and judge nothing but the call itself, in the order the proxy runs them:
/// <c>scanners.secrets.arguments: block</c>, then <c>scanners.arguments</c>.
/// Budgets, result scanners and approval act on a running session and are out
/// of scope for a file of static cases.
/// </remarks>
public static class PolicyTestRunner
{
    /// <summary>Parses a test file.</summary>
    /// <exception cref="PolicyException">The file is malformed.</exception>
    public static PolicyTestDocument Parse(string yaml)
    {
        ArgumentNullException.ThrowIfNull(yaml);

        JsonNode? json;
        try
        {
            json = YamlJson.Parse(yaml);
        }
        catch (YamlJsonException ex)
        {
            throw new PolicyException(ex.Message, ex);
        }

        PolicyTestDocument? document;
        try
        {
            document = json?.Deserialize(GuardrailsJsonContext.Default.PolicyTestDocument);
        }
        catch (JsonException ex)
        {
            throw new PolicyException($"Test file is not valid: {ex.Message}", ex);
        }

        if (string.IsNullOrWhiteSpace(document?.Policy))
        {
            throw new PolicyException("A test file names the policy it tests with 'policy:'.");
        }

        if (document.Cases is not { Count: > 0 })
        {
            throw new PolicyException("A test file needs at least one entry under 'cases:'.");
        }

        return document;
    }

    /// <summary>Runs every case.</summary>
    /// <param name="document">The parsed test file.</param>
    /// <param name="policyText">The contents of the file <see cref="PolicyTestDocument.Policy"/> names.</param>
    /// <exception cref="PolicyException">The policy, the pack or a case is malformed.</exception>
    public static PolicyTestReport Run(PolicyTestDocument document, string policyText)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(policyText);

        var policy = LoadPolicy(document, policyText);
        var gates = new Gates(
            new PolicyEvaluator(policy),
            new SecretGate(policy.EffectiveScanners.EffectiveSecrets),
            new ArgumentGate(policy.EffectiveScanners.EffectiveArguments));
        var tools = document.Tools ?? new Dictionary<string, PolicyTestTool>();
        var cases = document.Cases ?? [];

        return new PolicyTestReport([.. cases.Select((c, index) => RunCase(gates, tools, c, index + 1))]);
    }

    private static PolicyDocument LoadPolicy(PolicyTestDocument document, string policyText)
    {
        if (!PolicyPack.IsPack(policyText))
        {
            return PolicyLoader.Parse(policyText);
        }

        if (string.IsNullOrWhiteSpace(document.Server))
        {
            throw new PolicyException(
                $"'{document.Policy}' is a pack, so the test file needs 'server:' to fill in its server name.");
        }

        try
        {
            return PolicyPack.Parse(policyText).RenderPolicy(document.Server);
        }
        catch (PackException ex)
        {
            throw new PolicyException(ex.Message, ex);
        }
    }

    /// <summary>What decides a case, in the order the proxy applies it.</summary>
    private sealed record Gates(PolicyEvaluator Evaluator, SecretGate Secrets, ArgumentGate Arguments);

    private static PolicyTestCaseResult RunCase(
        Gates gates,
        IReadOnlyDictionary<string, PolicyTestTool> tools,
        PolicyTestCase testCase,
        int number)
    {
        var label = testCase.Name ?? $"case {number} ({testCase.Call})";

        if (string.IsNullOrWhiteSpace(testCase.Call))
        {
            throw new PolicyException($"Case {number} needs 'call:', the tool name to call.");
        }

        if (testCase.Expect is not { } expected)
        {
            throw new PolicyException($"{label}: needs 'expect:' (allow, deny or require_approval).");
        }

        var facts = Facts(tools, testCase, label);
        var decision = gates.Secrets.Apply(
            gates.Evaluator.Evaluate(facts, explain: true),
            facts.Arguments is null ? null : new Dictionary<string, JsonElement>(facts.Arguments, StringComparer.Ordinal));
        var outcome = gates.Arguments.Apply(decision, facts.ToolName, facts.Arguments);
        decision = outcome.Decision;

        string? failure = null;
        if (decision.Verdict != expected)
        {
            failure = $"expected {expected.ToWireName()}, got {decision.Verdict.ToWireName()} " +
                      $"from {Describe(decision.RuleName)}";
        }
        else if (testCase.Rule is { } rule && !string.Equals(rule, decision.RuleName, StringComparison.Ordinal))
        {
            failure = $"expected rule '{rule}' to decide, but {Describe(decision.RuleName)} did";
        }
        else if (testCase.ArgumentHits is { } hits &&
                 !hits.Order(StringComparer.Ordinal).SequenceEqual(outcome.Findings.Detectors.Order(StringComparer.Ordinal)))
        {
            failure = $"expected argument hits [{string.Join(", ", hits)}], got " +
                      $"[{string.Join(", ", outcome.Findings.Detectors)}]";
        }

        return new PolicyTestCaseResult(
            label,
            failure is null,
            failure,
            // Never null: the case was evaluated with explain on.
            failure is null ? [] : decision.Trail!);
    }

    private static string Describe(string? rule) => rule is null ? "the default (no rule matched)" : $"rule '{rule}'";

    /// <summary>The facts the proxy would build for this call.</summary>
    private static ToolCallFacts Facts(
        IReadOnlyDictionary<string, PolicyTestTool> tools,
        PolicyTestCase testCase,
        string label)
    {
        var call = testCase.Call!;
        var unknown = testCase.Unknown ?? false;
        var advertised = tools.TryGetValue(call, out var tool);

        if (unknown && advertised)
        {
            throw new PolicyException($"{label}: '{call}' is listed under 'tools:', so it cannot be 'unknown: true'.");
        }

        if (unknown)
        {
            // What the proxy sees for a name no server advertises: no server
            // and no hints, so server: conditions never match.
            return new ToolCallFacts(call, testCase.Arguments, Caller: Caller(testCase, label));
        }

        if (!advertised)
        {
            throw new PolicyException(
                $"{label}: '{call}' is not listed under 'tools:'. List it, or add 'unknown: true' " +
                "to test a call to a tool no server advertises.");
        }

        var separator = call.IndexOf(ToolNamespacer.Separator, StringComparison.Ordinal);
        if (separator <= 0)
        {
            throw new PolicyException(
                $"{label}: '{call}' is not a qualified name. Tools are called as <server>__<tool>, " +
                "the way the client sees them.");
        }

        // A tool listed with no value ("gh__x:") advertises no hints, like "{}".
        var hints = tool ?? new PolicyTestTool();
        return new ToolCallFacts(
            call,
            testCase.Arguments,
            new ToolAnnotationFacts(hints.ReadOnlyHint, hints.DestructiveHint, hints.IdempotentHint, hints.OpenWorldHint),
            call[..separator],
            Caller(testCase, label));
    }

    /// <summary>The caller the case describes, or null for none.</summary>
    /// <remarks>
    /// Groups without a principal are refused rather than tested: a validated
    /// token always names a principal, so such a case would pass or fail for a
    /// caller the proxy can never see.
    /// </remarks>
    private static CallerIdentity? Caller(PolicyTestCase testCase, string label)
    {
        if (testCase.Principal is { } principal)
        {
            return new CallerIdentity(principal, testCase.Groups ?? []);
        }

        return testCase.Groups is null
            ? null
            : throw new PolicyException(
                $"{label}: sets 'groups:' without 'principal:'. Every validated caller has a principal; " +
                "add one, or drop 'groups:' to test a call with no caller.");
    }
}
