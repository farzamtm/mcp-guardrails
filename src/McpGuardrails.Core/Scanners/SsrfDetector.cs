using System.Net;

namespace McpGuardrails.Core.Scanners;

/// <summary>
/// Finds URLs in a string that point at internal, loopback or cloud-metadata
/// addresses: the shape of a server-side request forgery.
/// </summary>
/// <remarks>
/// The threat: a fetch or browser tool runs on the user's machine or inside
/// their network, so a URL the model chose - or was steered into choosing by an
/// injected instruction - reaches places the internet cannot. The cloud metadata
/// address <c>169.254.169.254</c> hands out credentials to anything that asks.
///
/// <b>No DNS resolution.</b> The proxy judges the literal argument. Resolving
/// would make the check slow and network-dependent, and would still lose to DNS
/// rebinding, where a name resolves to a public address when checked and a
/// private one when used. That gap is documented rather than half-closed.
///
/// Encoded addresses are decoded the way the C library's <c>inet_aton</c> does -
/// <c>2130706433</c>, <c>0x7f.1</c> and <c>0177.0.0.1</c> are all 127.0.0.1 to
/// most HTTP clients - because an attacker writes whichever form the check
/// forgot. For the same reason the clean-up a URL parser does first is done
/// here too: tabs and newlines are deleted, escapes decoded and full-width or
/// enclosed characters folded (<see cref="ArgumentText"/>).
///
/// Linear in the input: at most two forward passes (the second only when the
/// value holds a tab or newline), a bounded look-back of a few letters at each
/// colon to read the scheme, and each authority read a constant number of times.
/// </remarks>
internal static class SsrfDetector
{
    // Long enough for "gopher", the longest scheme checked.
    private const int _maxSchemeLength = 6;

    /// <summary>True when the value contains a URL to an internal address.</summary>
    public static bool IsMatch(string value)
    {
        if (Scan(value))
        {
            return true;
        }

        // The URL standard and Python's urlsplit delete every tab, CR and LF
        // before parsing, so "ht\ttp://169.254.169.254/" is fetched as written
        // without them. Judged both ways: as written, a newline still ends a
        // URL in prose.
        return value.AsSpan().IndexOfAny('\t', '\n', '\r') >= 0 &&
               Scan(string.Concat(value.Where(c => !ArgumentText.IsStrippedFromUrls(c))));
    }

    private static bool Scan(string value)
    {
        var index = value.IndexOf(':');

        while (index >= 0)
        {
            var end = index + 1;

            // Never re-read an authority: a colon inside one (a port, an IPv6
            // literal) is not the start of another URL, and skipping past it is
            // what keeps the scan linear.
            if (Scheme(value, index) is { } scheme && Check(value, index + 1, scheme, out end))
            {
                return true;
            }

            index = end < value.Length ? value.IndexOf(':', end) : -1;
        }

        return false;
    }

    private enum SchemeKind
    {
        /// <summary>The host decides: http, https, ws, wss, ftp.</summary>
        Network,

        /// <summary>Dangerous whatever the host: file, gopher, dict.</summary>
        Always,
    }

    /// <summary>The scheme that ends at <paramref name="colon"/>, if it is one this detector cares about.</summary>
    private static SchemeKind? Scheme(string value, int colon)
    {
        var start = colon;

        while (start > 0 && colon - start <= _maxSchemeLength && char.IsAsciiLetter(value[start - 1]))
        {
            start--;
        }

        // A letter run longer than any scheme ("profile:"), or one glued to a
        // preceding word character, is not a scheme.
        if (start > 0 && (char.IsAsciiLetterOrDigit(value[start - 1]) || value[start - 1] is '+' or '-' or '.'))
        {
            return null;
        }

        return value.AsSpan(start, colon - start).ToString().ToLowerInvariant() switch
        {
            "http" or "https" or "ws" or "wss" or "ftp" => SchemeKind.Network,
            "file" or "gopher" or "dict" => SchemeKind.Always,
            _ => null,
        };
    }

    /// <summary>Reads the authority after a scheme and judges its host.</summary>
    /// <param name="end">Where the authority ended, so the caller can skip it.</param>
    private static bool Check(string value, int start, SchemeKind scheme, out int end)
    {
        // Browsers and most HTTP clients accept backslashes and any number of
        // slashes here, so this does too. At least one is required: without it
        // "http:" is a word in prose, not a URL.
        var index = start;
        while (IsSlash(value, index))
        {
            index++;
        }

        end = index;

        if (index == start)
        {
            return false;
        }

        if (scheme is SchemeKind.Always)
        {
            return true;
        }

        // Two readings of where the host is, and either one being internal is
        // a hit. Read as prose, the authority also ends at a quote, a bracket,
        // a comma or a space, so "(http://127.0.0.1)" and "http://10.0.0.1, then"
        // are found. A URL parser ends it only at the path, query or fragment,
        // and takes everything up to the last '@' before that as userinfo -
        // whatever it contains - so "http://a,@169.254.169.254/" goes to the
        // metadata address.
        var authorityEnd = index;
        while (authorityEnd < value.Length && !EndsUrlAuthority(value[authorityEnd]))
        {
            authorityEnd++;
        }

        while (end < authorityEnd && !EndsProseAuthority(value[end]))
        {
            end++;
        }

        if (IsInternalHost(Host(value.AsSpan(index, end - index))))
        {
            return true;
        }

        // The prose reading already took a '@' inside its own span into account.
        var at = value.AsSpan(end, authorityEnd - end).LastIndexOf('@');
        if (at < 0)
        {
            return false;
        }

        var hostStart = end + at + 1;
        var hostEnd = hostStart;
        while (hostEnd < authorityEnd && !EndsProseAuthority(value[hostEnd]))
        {
            hostEnd++;
        }

        // The caller resumes at the end of the prose reading, not past the
        // '@': a URL between the two would otherwise be skipped. Nothing
        // between them is read again by another authority, because the next
        // URL's slashes end this one's span, so the scan stays linear.
        return IsInternalHost(Host(value.AsSpan(hostStart, hostEnd - hostStart)));
    }

    private static bool IsSlash(string value, int index) =>
        index < value.Length && ArgumentText.IsSeparator(value[index]);

    private static bool EndsUrlAuthority(char c) => ArgumentText.IsSeparator(c) || c is '?' or '#';

    private static bool EndsProseAuthority(char c) =>
        EndsUrlAuthority(c) || c is '"' or '\'' or '`' or '<' or '>' or ')' or ',' || char.IsWhiteSpace(c);

    /// <summary>The host part of an authority, decoded and normalised.</summary>
    private static string Host(ReadOnlySpan<char> authority)
    {
        // Userinfo ends at the LAST '@': "http://evil.com@127.0.0.1/" goes to
        // 127.0.0.1, which is exactly the confusion it is written to exploit.
        var at = authority.LastIndexOf('@');
        var host = authority[(at + 1)..];

        if (host.StartsWith('['))
        {
            var close = host.IndexOf(']');
            host = close < 0 ? host[1..] : host[1..close];
        }
        else if (host.IndexOf(':') is var colon and >= 0)
        {
            host = host[..colon];
        }

        // Escapes are decoded first, then full-width, enclosed and ideographic
        // forms folded, the order a URL parser applies before IDNA: a client
        // resolving "%EF%BC%91２７。0。0。1" connects to loopback.
        return ArgumentText.FoldHost(ArgumentText.Decode(host.ToString()))
            .ToLowerInvariant()
            .TrimEnd('.');
    }

    internal static bool IsInternalHost(string host)
    {
        if (host is "localhost" || host.EndsWith(".localhost", StringComparison.Ordinal) ||
            host.EndsWith(".internal", StringComparison.Ordinal))
        {
            return true;
        }

        if (TryParseIPv4(host, out var v4))
        {
            return IsInternal(v4);
        }

        // Only reached for a bracketed literal: an unbracketed host had its
        // first colon taken as the port separator. With a colon in it, only an
        // IPv6 address parses - IPAddress refuses "1.2.3.4:80" - so what
        // TryParse accepts here is always IPv6.
        return host.Contains(':') && IPAddress.TryParse(host, out var address) && IsInternal(address);
    }

    /// <summary>Parses a host the way <c>inet_aton</c> does: 1 to 4 parts, each decimal, octal or hex.</summary>
    internal static bool TryParseIPv4(string host, out uint address)
    {
        address = 0;

        var parts = host.Split('.');
        if (host.Length == 0 || parts.Length > 4)
        {
            return false;
        }

        var values = new ulong[parts.Length];
        for (var i = 0; i < parts.Length; i++)
        {
            if (!TryParsePart(parts[i], out values[i]))
            {
                return false;
            }
        }

        // The last part fills every byte the earlier ones did not: "127.1" is
        // 127.0.0.1 and "10.1.257" is 10.1.1.1.
        var last = values[^1];
        var lastBits = 8 * (5 - parts.Length);
        if (last >> lastBits != 0)
        {
            return false;
        }

        ulong result = last;
        for (var i = 0; i < parts.Length - 1; i++)
        {
            if (values[i] > 0xFF)
            {
                return false;
            }

            result |= values[i] << (24 - (8 * i));
        }

        address = (uint)result;
        return true;
    }

    private static bool TryParsePart(string part, out ulong value)
    {
        value = 0;

        var (digits, radix) = part switch
        {
            ['0', 'x' or 'X', .. var rest] => (rest, 16),
            ['0', _, ..] => (part[1..], 8),
            _ => (part, 10),
        };

        if (digits.Length == 0)
        {
            return false;
        }

        // inet_aton and the URL standard accept any number of leading zeros, so
        // "0x00000000007f000001" is loopback. Only the significant digits are
        // limited: past 11 no 32-bit value can be written even in octal, so no
        // overflow check is needed below.
        var significant = digits.TrimStart('0');
        if (significant.Length > 11)
        {
            return false;
        }

        foreach (var c in significant)
        {
            var digit = char.IsAsciiDigit(c) ? c - '0'
                : char.IsAsciiHexDigit(c) ? char.ToLowerInvariant(c) - 'a' + 10
                : radix;

            if (digit >= radix)
            {
                return false;
            }

            value = (value * (ulong)radix) + (ulong)digit;
        }

        return true;
    }

    internal static bool IsInternal(uint ip) =>
        (ip >> 24) is 0 or 10 or 127 ||
        (ip & 0xFFF00000) == 0xAC100000 || // 172.16.0.0/12
        (ip & 0xFFFF0000) == 0xC0A80000 || // 192.168.0.0/16
        (ip & 0xFFFF0000) == 0xA9FE0000 || // 169.254.0.0/16, incl. cloud metadata
        (ip & 0xFFC00000) == 0x64400000; // 100.64.0.0/10, carrier-grade NAT

    private static bool IsInternal(IPAddress address)
    {
        if (address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.IPv6Loopback) ||
            address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal)
        {
            return true;
        }

        var bytes = address.GetAddressBytes();

        // An IPv4 address inside an IPv6 one reaches the IPv4 address: mapped
        // (::ffff:a.b.c.d), compatible (::a.b.c.d), NAT64 (64:ff9b::a.b.c.d) and
        // 6to4 (2002:aabb:ccdd::), the last of which carries it in bytes 2-5.
        if (address.IsIPv4MappedToIPv6 || IsZero(bytes, 0, 12) ||
            (bytes[0] == 0x00 && bytes[1] == 0x64 && bytes[2] == 0xFF && bytes[3] == 0x9B && IsZero(bytes, 4, 8)))
        {
            return IsInternal(ToUInt32(bytes, 12));
        }

        return bytes[0] == 0x20 && bytes[1] == 0x02 && IsInternal(ToUInt32(bytes, 2));
    }

    private static bool IsZero(byte[] bytes, int start, int count) =>
        bytes.AsSpan(start, count).IndexOfAnyExcept((byte)0) < 0;

    private static uint ToUInt32(byte[] bytes, int start) =>
        ((uint)bytes[start] << 24) | ((uint)bytes[start + 1] << 16) | ((uint)bytes[start + 2] << 8) | bytes[start + 3];
}
