namespace McpGuardrails.Core.Scanners;

/// <summary>
/// The two path detectors: reads of credential files, and <c>..</c> traversal.
/// </summary>
/// <remarks>
/// Both classify what was <i>asked</i>. Whether a path actually escapes its
/// sandbox is the server's question to answer - only it knows its root, its
/// symlinks and its working directory - and the policy docs already say not to
/// rely on a guardrail for containment. What the proxy can do is notice the
/// shapes an attacker reaches for and say so, before the server is asked.
///
/// Matching is case-insensitive on every platform. The default file systems on
/// macOS and Windows are case-insensitive, so <c>~/.SSH/ID_RSA</c> is the key
/// file there, and a false positive under the default <c>audit</c> costs only a
/// log field.
/// </remarks>
internal static class PathDetectors
{
    private static readonly HashSet<string> _credentialFiles = new(StringComparer.Ordinal)
    {
        ".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials", ".env", ".pgpass",
        // Browser credential and cookie stores, named distinctively enough to
        // flag without knowing which profile directory they sit in.
        "login data", "logins.json", "key3.db", "key4.db", "cookies.sqlite", "signons.sqlite",
    };

    private static readonly HashSet<string> _privateKeys = new(StringComparer.Ordinal)
    {
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk",
    };

    private static readonly HashSet<string> _browserDirectories = new(StringComparer.Ordinal)
    {
        "chrome", "chromium", "google-chrome", "brave-browser", "bravesoftware", "microsoft edge", "edge",
        "firefox", "mozilla", "opera software", "vivaldi",
    };

    // Directory sequences, matched as whole consecutive segments anywhere in a
    // path, so "/home/u/.aws/credentials" and "C:\Users\u\.aws\credentials"
    // both match while "aws-credentials-guide.md" does not.
    private static readonly string[][] _credentialSequences =
    [
        [".aws", "credentials"],
        [".config", "gcloud"],
        [".kube", "config"],
        [".docker", "config.json"],
        ["etc", "shadow"],
        ["etc", "gshadow"],
        ["etc", "sudoers"],
        ["etc", "sudoers.d"],
        ["library", "keychains"],
        ["appdata", "roaming", "microsoft", "credentials"],
        ["appdata", "local", "microsoft", "credentials"],
    ];

    /// <summary>
    /// True for a path separator, including the Unicode look-alikes that some
    /// path and URL normalisers fold into one.
    /// </summary>
    public static bool IsSeparator(char c) => c is '/' or '\\' or '∕' or '⁄' or '／' or '＼' or '⧵';

    /// <summary>True when the value names a credential file.</summary>
    /// <param name="value">The argument value.</param>
    /// <param name="pathNamed">
    /// The argument's name says it holds a path (<c>path</c>, <c>file</c>,
    /// <c>destination</c>...), so the whole value is one path even if it has
    /// spaces in it.
    /// </param>
    /// <remarks>
    /// Otherwise a value with whitespace is prose or a command line, and only its
    /// words that contain a separator are read as paths. That is the line between
    /// "cat ~/.ssh/id_rsa", which is flagged, and "remember to add .env to
    /// .gitignore", which is not.
    /// </remarks>
    public static bool IsSensitivePath(string value, bool pathNamed)
    {
        if (pathNamed || !value.AsSpan().ContainsAny(_whitespace))
        {
            return IsSensitive(value);
        }

        var start = 0;
        for (var i = 0; i <= value.Length; i++)
        {
            if (i < value.Length && !IsWordBreak(value[i]))
            {
                continue;
            }

            var word = value.AsSpan(start, i - start);
            if (ContainsSeparator(word) && IsSensitive(word.ToString()))
            {
                return true;
            }

            start = i + 1;
        }

        return false;
    }

    private static readonly System.Buffers.SearchValues<char> _whitespace =
        System.Buffers.SearchValues.Create(" \t\r\n\f\v\u00a0\u2028\u2029\u3000");

    private static bool IsWordBreak(char c) => char.IsWhiteSpace(c) || c is '"' or '\'' or '`';

    private static bool ContainsSeparator(ReadOnlySpan<char> word)
    {
        foreach (var c in word)
        {
            if (IsSeparator(c))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsSensitive(string path)
    {
        var segments = Segments(path);

        var browser = false;
        foreach (var segment in segments)
        {
            browser |= _browserDirectories.Contains(segment);
        }

        for (var i = 0; i < segments.Count; i++)
        {
            var segment = segments[i];

            if (segment is ".ssh" || _privateKeys.Contains(segment) || _credentialFiles.Contains(segment) ||
                IsEnvVariant(segment) || (browser && segment is "cookies" or "web data") ||
                StartsSequence(segments, i))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// <c>.env.local</c>, <c>.env.production</c> - but not the templates a
    /// project commits on purpose, which hold placeholders rather than secrets.
    /// </summary>
    private static bool IsEnvVariant(string segment) =>
        segment.StartsWith(".env.", StringComparison.Ordinal) &&
        !segment.EndsWith(".example", StringComparison.Ordinal) &&
        !segment.EndsWith(".sample", StringComparison.Ordinal) &&
        !segment.EndsWith(".template", StringComparison.Ordinal);

    private static bool StartsSequence(List<string> segments, int index)
    {
        foreach (var sequence in _credentialSequences)
        {
            if (Matches(segments, index, sequence))
            {
                return true;
            }
        }

        return false;
    }

    private static bool Matches(List<string> segments, int index, string[] sequence)
    {
        if (index + sequence.Length > segments.Count)
        {
            return false;
        }

        for (var j = 0; j < sequence.Length; j++)
        {
            if (segments[index + j] != sequence[j])
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>The path's segments, lower-cased, with escapes decoded and separators unified.</summary>
    private static List<string> Segments(string path)
    {
        var decoded = SsrfDetector.PercentDecode(path).ToLowerInvariant();
        var segments = new List<string>();

        var start = 0;
        for (var i = 0; i <= decoded.Length; i++)
        {
            if (i < decoded.Length && !IsSeparator(decoded[i]))
            {
                continue;
            }

            if (i > start)
            {
                segments.Add(decoded[start..i]);
            }

            start = i + 1;
        }

        return segments;
    }

    /// <summary>
    /// True when the value has a <c>..</c> segment next to a separator, written
    /// plainly or in any of the encodings servers have been fooled by.
    /// </summary>
    /// <remarks>
    /// Read as a stream of tokens - dot, separator, word break, anything else -
    /// so the encodings are recognised in place without decoding the value
    /// first, and a double-encoded <c>%252e</c> or an overlong UTF-8
    /// <c>%c0%ae</c> is one token like a literal dot. One pass, constant work
    /// per character.
    /// </remarks>
    public static bool HasTraversal(string value)
    {
        var dots = 0;
        var other = false;
        var afterSeparator = false;

        var i = 0;
        while (i <= value.Length)
        {
            var (token, length) = i < value.Length ? Token(value, i) : (PathToken.Break, 1);

            if (token is PathToken.Dot)
            {
                dots++;
            }
            else if (token is PathToken.Other)
            {
                other = true;
            }
            else
            {
                // A segment of exactly two dots is "..". It counts when a
                // separator is on either side of it; ".." alone, or "wait..",
                // is punctuation.
                if (dots == 2 && !other && (afterSeparator || token is PathToken.Separator))
                {
                    return true;
                }

                dots = 0;
                other = false;
                afterSeparator = token is PathToken.Separator;
            }

            i += length;
        }

        return false;
    }

    private enum PathToken
    {
        Dot,
        Separator,
        Break,
        Other,
    }

    // Each encoding and what it decodes to. Hex is matched case-insensitively.
    private static readonly (string Text, PathToken Token)[] _encodings =
    [
        ("%2e", PathToken.Dot),
        ("%2f", PathToken.Separator),
        ("%5c", PathToken.Separator),
        // Double-encoded: %25 is '%'.
        ("%252e", PathToken.Dot),
        ("%252f", PathToken.Separator),
        ("%255c", PathToken.Separator),
        // Overlong UTF-8, which lenient decoders turn into ASCII.
        ("%c0%ae", PathToken.Dot),
        ("%c0%af", PathToken.Separator),
        ("%c1%9c", PathToken.Separator),
        ("%e0%80%ae", PathToken.Dot),
        ("%e0%80%af", PathToken.Separator),
        // IIS-style %u escapes.
        ("%u002e", PathToken.Dot),
        ("%u002f", PathToken.Separator),
        ("%u005c", PathToken.Separator),
        ("%u2215", PathToken.Separator),
    ];

    private static (PathToken Token, int Length) Token(string value, int index)
    {
        var c = value[index];

        if (c == '%')
        {
            // Longest first would matter if one encoding prefixed another with a
            // different meaning; none does, so the first match is the only one.
            foreach (var (text, token) in _encodings)
            {
                if (value.AsSpan(index).StartsWith(text, StringComparison.OrdinalIgnoreCase))
                {
                    return (token, text.Length);
                }
            }

            return (PathToken.Other, 1);
        }

        return c switch
        {
            '.' or '．' or '․' => (PathToken.Dot, 1),
            _ when IsSeparator(c) => (PathToken.Separator, 1),
            _ when char.IsWhiteSpace(c) || c is '"' or '\'' or '`' or '=' or ',' or ';' or '(' or ')' or '[' or ']'
                or '{' or '}' or '<' or '>' or '|' or '&' => (PathToken.Break, 1),
            _ => (PathToken.Other, 1),
        };
    }
}
