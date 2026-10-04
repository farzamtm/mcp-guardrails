using System.Text.Json;
using System.Text.Json.Nodes;
using McpGuardrails.Core.Budget;
using McpGuardrails.Core.Serialization;

namespace McpGuardrails.Core.Policy;

/// <summary>
/// Reads a YAML policy file into a <see cref="PolicyDocument"/>.
/// </summary>
/// <remarks>
/// The two-stage conversion (YAML to JsonNode to typed object) is deliberate and
/// is the mitigation for reflection under Native AOT; see <see cref="YamlJson"/>.
/// </remarks>
public static class PolicyLoader
{
    /// <summary>
    /// Loads the policy at <paramref name="path"/>, or an empty policy if there
    /// is no file there.
    /// </summary>
    /// <remarks>
    /// A missing file is normal - it is the passthrough default that makes the
    /// proxy adoptable. A malformed file throws: failing open because the policy
    /// would not parse is the worst possible behaviour for a security tool.
    /// </remarks>
    public static PolicyDocument LoadFromFileOrEmpty(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        // A directory is not "no policy". File.Exists returns false for one, so
        // without this check a misconfigured path would fall through to the empty
        // policy and allow everything - a silent fail-open, which is the single
        // worst failure mode available to this component.
        if (Directory.Exists(path))
        {
            throw new PolicyException(
                $"Could not read the policy file: '{path}' is a directory, not a file.");
        }

        // A genuinely absent file IS "no policy": passthrough with audit logging.
        if (!File.Exists(path))
        {
            return PolicyDocument.Empty;
        }

        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (IOException ex)
        {
            throw new PolicyException($"Could not read the policy file: {ex.Message}", ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new PolicyException($"Could not read the policy file: {ex.Message}", ex);
        }

        return Parse(text);
    }

    /// <summary>Parses policy YAML from a string.</summary>
    public static PolicyDocument Parse(string yaml)
    {
        ArgumentNullException.ThrowIfNull(yaml);

        // An empty or comments-only document is a valid "no rules" policy.
        if (string.IsNullOrWhiteSpace(yaml))
        {
            return PolicyDocument.Empty;
        }

        JsonNode? json;
        try
        {
            json = YamlJson.Parse(yaml);
        }
        catch (YamlJsonException ex)
        {
            throw new PolicyException(ex.Message, ex);
        }

        if (json is null)
        {
            return PolicyDocument.Empty;
        }

        PolicyDocument document;
        try
        {
            // Never null: a null root returned early above, and anything else
            // that is not a mapping throws rather than binding to nothing.
            document = json.Deserialize(GuardrailsJsonContext.Default.PolicyDocument)!;
        }
        catch (JsonException ex)
        {
            throw new PolicyException($"Policy file is not valid: {ex.Message}", ex);
        }

        // Fail at load time rather than on the first tool call, so a typo is
        // caught when the proxy starts instead of hours later mid-session.
        foreach (var rule in document.EffectiveRules)
        {
            rule.Validate();
        }

        document.EffectiveBudgets.Validate();
        document.EffectiveApprovers.Validate(document.EffectiveRules);
        document.EffectiveScanners.Validate();
        document.EffectiveAccess.Validate();
        RequireIdentitySource(document);

        return document;
    }

    /// <summary>
    /// Refuses identity conditions and per-principal budgets in a policy that
    /// has nowhere to get an identity from.
    /// </summary>
    /// <remarks>
    /// Without <c>access.oauth</c> no call has a principal, so a
    /// <c>principal:</c> rule would never match and a <c>budgets.principal</c>
    /// cap would never be charged. A deny rule or a cap that silently does
    /// nothing is the fail-open this check exists to prevent.
    /// </remarks>
    private static void RequireIdentitySource(PolicyDocument document)
    {
        if (document.EffectiveAccess.OAuth is not null)
        {
            return;
        }

        if (document.EffectiveRules.FirstOrDefault(rule => rule.EffectiveMatch.UsesIdentity) is { } rule)
        {
            throw new PolicyException(
                $"Rule '{rule.Name}' matches on 'principal' or 'groups', but the policy has no " +
                "'access.oauth' section, so no call would ever carry an identity and the rule would " +
                "never match. Configure 'access.oauth', or remove the condition.");
        }

        if (document.EffectiveBudgets.Principal is not null)
        {
            throw new PolicyException(
                $"'budgets.{BudgetGate.PrincipalScope}' needs 'access.oauth': without it no call has a " +
                "principal to charge, so the cap would never apply.");
        }
    }
}
