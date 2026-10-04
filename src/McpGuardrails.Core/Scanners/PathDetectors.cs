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
    private static readonly HashSet<string> _credentialFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        ".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials", ".env", ".pgpass",
        // Browser credential and cookie stores, named distinctively enough to
        // flag without knowing which profile directory they sit in.
        "login data", "logins.json", "key3.db", "key4.db", "cookies.sqlite", "signons.sqlite",
    };

    private static readonly HashSet<string> _privateKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk",
    };

    private static readonly HashSet<string> _browserDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "chromium", "google-chrome", "brave-browser", "bravesoftware", "microsoft edge", "edge",
        "firefox", "mozilla", "opera software", "vivaldi",
    };

    // Looked up by span, so a segment is compared where it lies in the value
    // rather than copied and lower-cased first.
    private static readonly HashSet<string>.AlternateLookup<ReadOnlySpan<char>> _credentialFileLookup =
        _credentialFiles.GetAlternateLookup<ReadOnlySpan<char>>();

    private static readonly HashSet<string>.AlternateLookup<ReadOnlySpan<char>> _privateKeyLookup =
        _privateKeys.GetAlternateLookup<ReadOnlySpan<char>>();

    private static readonly HashSet<string>.AlternateLookup<ReadOnlySpan<char>> _browserDirectoryLookup =
        _browserDirectories.GetAlternateLookup<ReadOnlySpan<char>>();

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

    /// <summary>True when the value names a credential file.</summary>
    /// <param name="value">The argument value.</param>
    /// <param name="pathNamed">
    /// The argument's name says it holds a path (<c>path</c>, <c>file</c>,
    /// <c>destination</c>...), so the whole value is one path even if it has
    /// spaces in it.
    /// </param>
    /// <param name="command">
    /// The value is a command line, so a quoted word is one path even if it has
    /// spaces in it: <c>cp "~/Library/Application Support/Google/Chrome/Default/Login Data" /tmp</c>.
    /// </param>
    /// <remarks>
    /// Otherwise a value with whitespace is prose or a command line, and only its
    /// words that contain a separator are read as paths. That is the line between
    /// "cat ~/.ssh/id_rsa", which is flagged, and "remember to add .env to
    /// .gitignore", which is not.
    /// </remarks>
    public static bool IsSensitivePath(string value, bool pathNamed, bool command = false)
    {
        if (pathNamed || !ArgumentText.HasWhitespace(value))
        {
            return IsSensitive(value);
        }

        return AnyWord(value) || (command && AnyQuotedWord(value));
    }

    private static bool AnyWord(string value)
    {
        var start = 0;
        for (var i = 0; i <= value.Length; i++)
        {
            if (i < value.Length && !ArgumentText.IsWordBreak(value[i]))
            {
                continue;
            }

            if (IsSensitiveWord(value.AsSpan(start, i - start)))
            {
                return true;
            }

            start = i + 1;
        }

        return false;
    }

    /// <summary>
    /// Reads a command line the way a shell splits it: a quoted run is one word,
    /// spaces included, and anything else ends at whitespace.
    /// </summary>
    private static bool AnyQuotedWord(string value)
    {
        var i = 0;
        while (i < value.Length)
        {
            if (char.IsWhiteSpace(value[i]))
            {
                i++;
                continue;
            }

            int start;
            int end;
            if (value[i] is '"' or '\'')
            {
                var quote = value[i];
                start = i + 1;
                end = value.IndexOf(quote, start);
                end = end < 0 ? value.Length : end;
                i = end + 1;
            }
            else
            {
                start = i;
                while (i < value.Length && !char.IsWhiteSpace(value[i]) && value[i] is not ('"' or '\''))
                {
                    i++;
                }

                end = i;
            }

            if (IsSensitiveWord(value.AsSpan(start, end - start)))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsSensitiveWord(ReadOnlySpan<char> word) =>
        word.ContainsAny(_separators) && IsSensitive(word.ToString());

    private static readonly System.Buffers.SearchValues<char> _separators =
        System.Buffers.SearchValues.Create("/\\∕⁄／＼⧵");

    private static bool IsSensitive(string path)
    {
        var decoded = ArgumentText.Decode(path);
        var segments = Segments(decoded);

        var browser = false;
        foreach (var segment in segments)
        {
            browser |= _browserDirectoryLookup.Contains(decoded.AsSpan(segment));
        }

        for (var i = 0; i < segments.Count; i++)
        {
            var segment = decoded.AsSpan(segments[i]);

            if (segment.Equals(".ssh", StringComparison.OrdinalIgnoreCase) ||
                _privateKeyLookup.Contains(segment) || _credentialFileLookup.Contains(segment) ||
                IsEnvVariant(segment) ||
                (browser && (segment.Equals("cookies", StringComparison.OrdinalIgnoreCase) ||
                             segment.Equals("web data", StringComparison.OrdinalIgnoreCase))) ||
                StartsSequence(decoded, segments, i))
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
    private static bool IsEnvVariant(ReadOnlySpan<char> segment) =>
        segment.StartsWith(".env.", StringComparison.OrdinalIgnoreCase) &&
        !segment.EndsWith(".example", StringComparison.OrdinalIgnoreCase) &&
        !segment.EndsWith(".sample", StringComparison.OrdinalIgnoreCase) &&
        !segment.EndsWith(".template", StringComparison.OrdinalIgnoreCase);

    private static bool StartsSequence(string path, List<Range> segments, int index)
    {
        foreach (var sequence in _credentialSequences)
        {
            if (Matches(path, segments, index, sequence))
            {
                return true;
            }
        }

        return false;
    }

    private static bool Matches(string path, List<Range> segments, int index, string[] sequence)
    {
        if (index + sequence.Length > segments.Count)
        {
            return false;
        }

        for (var j = 0; j < sequence.Length; j++)
        {
            if (!path.AsSpan(segments[index + j]).Equals(sequence[j], StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// The path's segments as the file system resolves them: separators unified,
    /// <c>.</c> dropped, <c>..</c> taking back the segment before it, and the
    /// Windows spellings of a name trimmed to the name itself.
    /// </summary>
    /// <remarks>
    /// Otherwise <c>~/.aws/./credentials</c> or <c>/etc/x/../shadow</c> would
    /// break a sequence the operating system reads straight through, and
    /// <c>id_rsa.</c> or <c>.env::$DATA</c> would open the file on Windows -
    /// which strips trailing dots and spaces and reads the default data stream -
    /// without matching its name.
    /// </remarks>
    private static List<Range> Segments(string path)
    {
        var segments = new List<Range>();

        var start = 0;
        for (var i = 0; i <= path.Length; i++)
        {
            if (i < path.Length && !ArgumentText.IsSeparator(path[i]))
            {
                continue;
            }

            var segment = Trim(path, start, i);
            start = i + 1;

            if (segment.Start.Value == segment.End.Value || path.AsSpan(segment) is ".")
            {
                continue;
            }

            if (path.AsSpan(segment) is "..")
            {
                if (segments.Count > 0)
                {
                    segments.RemoveAt(segments.Count - 1);
                }

                continue;
            }

            segments.Add(segment);
        }

        return segments;
    }

    private static Range Trim(string path, int start, int end)
    {
        var segment = path.AsSpan(start, end - start);

        // "." and ".." are directory references, not names with trailing dots.
        if (segment is "." or "..")
        {
            return start..end;
        }

        if (segment.EndsWith("::$data", StringComparison.OrdinalIgnoreCase))
        {
            end -= "::$data".Length;
        }

        while (end > start && path[end - 1] is '.' or ' ')
        {
            end--;
        }

        return start..end;
    }

    /// <summary>
    /// True when the value has a <c>..</c> segment next to a separator, written
    /// plainly or in any of the encodings servers have been fooled by.
    /// </summary>
    /// <remarks>
    /// Decoded first with the same rules as <c>sensitive-path</c>, so a
    /// double-encoded <c>%252e</c>, an overlong UTF-8 <c>%c0%ae</c> or an IIS
    /// <c>%u002e</c> is a dot like a literal one, then read as a stream of
    /// tokens - dot, separator, word break, anything else. Constant work per
    /// character.
    /// </remarks>
    public static bool HasTraversal(string value)
    {
        value = ArgumentText.Decode(value);

        var dots = 0;
        var other = false;
        var afterSeparator = false;

        for (var i = 0; i <= value.Length; i++)
        {
            var token = i < value.Length ? Token(value[i]) : PathToken.Break;

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

    private static PathToken Token(char c) => c switch
    {
        '.' or '．' or '․' => PathToken.Dot,
        _ when ArgumentText.IsSeparator(c) => PathToken.Separator,
        _ when char.IsWhiteSpace(c) || c is '"' or '\'' or '`' or '=' or ',' or ';' or '(' or ')' or '[' or ']'
            or '{' or '}' or '<' or '>' or '|' or '&' => PathToken.Break,
        _ => PathToken.Other,
    };
}
