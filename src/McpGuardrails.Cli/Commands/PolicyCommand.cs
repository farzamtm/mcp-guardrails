using McpGuardrails.Core.Policy;

namespace McpGuardrails.Cli.Commands;

/// <summary>
/// <c>policy test &lt;file&gt;...</c>: runs policy test files and reports every
/// case that got a different decision than it expected.
/// </summary>
/// <remarks>
/// Exit 0 when every case in every file passes, 1 otherwise - so CI can gate on
/// a policy behaving, not just parsing. Each failure prints the decision trail
/// that <c>--explain</c> would, because "expected deny, got allow" is only half
/// an answer.
/// </remarks>
internal sealed class PolicyCommand : ICliCommand
{
    private const string _usage = "_usage: mcp-guardrails policy test <test-file>...";

    public async Task<int> RunAsync(string[] args)
    {
        var index = Array.IndexOf(args, "policy");
        if (index + 1 >= args.Length || args[index + 1] != "test")
        {
            throw new CommandFailedException(2, _usage);
        }

        var files = args[(index + 2)..].Where(arg => !arg.StartsWith('-')).ToList();
        if (files.Count == 0)
        {
            throw new CommandFailedException(2, _usage);
        }

        var failed = false;
        foreach (var file in files)
        {
            failed |= !await RunFileAsync(file);
        }

        return failed ? 1 : 0;
    }

    private static async Task<bool> RunFileAsync(string file)
    {
        PolicyTestReport report;
        try
        {
            var document = PolicyTestRunner.Parse(await File.ReadAllTextAsync(file));

            // Relative to the test file, so a test and its policy can sit side
            // by side and be run from anywhere.
            var policyPath = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(file))!, document.Policy!);
            report = PolicyTestRunner.Run(document, await File.ReadAllTextAsync(policyPath));
        }
        catch (Exception ex) when (ex is PolicyException or IOException or UnauthorizedAccessException)
        {
            Console.WriteLine($"{file}: error: {ex.Message}");
            return false;
        }

        var failures = report.Failures;
        Console.WriteLine(failures.Count == 0
            ? $"{file}: {report.Cases.Count} passed"
            : $"{file}: {failures.Count} of {report.Cases.Count} failed");

        foreach (var failure in failures)
        {
            Console.WriteLine($"  FAIL {failure.Label}: {failure.Failure}");
            foreach (var step in failure.Trail)
            {
                Console.WriteLine($"         {step}");
            }
        }

        return failures.Count == 0;
    }
}
