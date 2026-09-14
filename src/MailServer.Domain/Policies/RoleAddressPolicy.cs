namespace MailServer.Domain.Policies;

/// <summary>How strongly a role address is expected to exist.</summary>
public enum RoleAddressExpectation
{
    /// <summary>Required by RFC 5321 §4.5.1. Its absence is a standards violation.</summary>
    Required = 0,

    /// <summary>
    /// Expected by convention and by receivers. Its absence has practical consequences.
    /// </summary>
    Expected = 1,

    /// <summary>Useful where the corresponding service is offered.</summary>
    Conditional = 2,
}

/// <summary>One RFC 2142 role address.</summary>
/// <param name="LocalPart">The local-part, e.g. <c>postmaster</c>.</param>
/// <param name="Expectation">How strongly it is expected.</param>
/// <param name="Purpose">What it is for, and what happens without it.</param>
public sealed record RoleAddress(
    string LocalPart,
    RoleAddressExpectation Expectation,
    string Purpose);

/// <summary>
/// The role addresses a hosted domain is expected to answer, from RFC 2142 and RFC 5321.
/// </summary>
/// <remarks>
/// <para>
/// <b>These are not decoration.</b> <c>postmaster@</c> is required by RFC 5321 §4.5.1 — a
/// server must accept mail for it — and it is the address a remote administrator uses when
/// mail from this server is being rejected. A domain that does not answer it has removed the
/// one channel through which a delivery problem gets reported.
/// </para>
/// <para>
/// <c>abuse@</c> is what a recipient network contacts before it blocks a sending IP. Missing
/// it does not prevent the block; it prevents the warning that would have come first, and
/// abuse.net and several blocklist operators check for it explicitly.
/// </para>
/// <para>
/// The server does not create these automatically. It reports them as a readiness finding, and
/// the operator decides whether each is a mailbox or an alias to one — which is the right
/// decision for them to make, since on most domains they should all be aliases to one person.
/// </para>
/// </remarks>
public static class RoleAddressPolicy
{
    /// <summary>Every role address this server checks for.</summary>
    public static IReadOnlyList<RoleAddress> All { get; } =
    [
        new("postmaster", RoleAddressExpectation.Required,
            "Required by RFC 5321 §4.5.1. This is how a remote administrator reports that " +
            "mail from this domain is being rejected. Without it, the first sign of a problem " +
            "is silence."),

        new("abuse", RoleAddressExpectation.Expected,
            "Where a recipient network reports spam or compromise originating here — usually " +
            "before it blocks the sending IP rather than after. Blocklist operators check for " +
            "it."),

        new("hostmaster", RoleAddressExpectation.Expected,
            "DNS administration contact, and the address conventionally named in the SOA " +
            "record's RNAME field."),

        new("webmaster", RoleAddressExpectation.Conditional,
            "Expected where the domain also serves a website."),

        new("security", RoleAddressExpectation.Conditional,
            "Where vulnerability reports arrive. Worth having wherever the domain runs a " +
            "service somebody might report a flaw in."),
    ];

    /// <summary>The ones whose absence should be reported as a problem rather than a hint.</summary>
    public static IReadOnlyList<RoleAddress> RequiredAndExpected { get; } =
    [
        .. All.Where(static r => r.Expectation != RoleAddressExpectation.Conditional),
    ];

    /// <summary>True when <paramref name="localPart"/> is one of the role addresses.</summary>
    /// <remarks>
    /// Case-insensitive, because RFC 2142 specifies these names case-insensitively and a
    /// mailbox at <c>Postmaster</c> satisfies the requirement exactly as well as one at
    /// <c>postmaster</c>.
    /// </remarks>
    public static bool IsRoleAddress(string localPart) =>
        All.Any(r => string.Equals(r.LocalPart, localPart, StringComparison.OrdinalIgnoreCase));

    /// <summary>Looks up a role address by local-part.</summary>
    public static RoleAddress? Find(string localPart) =>
        All.FirstOrDefault(r =>
            string.Equals(r.LocalPart, localPart, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Which expected role addresses a domain is missing.
    /// </summary>
    /// <param name="existingLocalParts">
    /// Every local-part the domain answers, whether as a mailbox or an alias — an alias to a
    /// real person satisfies the requirement perfectly, and is usually the better arrangement.
    /// </param>
    public static IReadOnlyList<RoleAddress> FindMissing(IEnumerable<string> existingLocalParts)
    {
        ArgumentNullException.ThrowIfNull(existingLocalParts);

        HashSet<string> existing = new(existingLocalParts, StringComparer.OrdinalIgnoreCase);

        return [.. RequiredAndExpected.Where(r => !existing.Contains(r.LocalPart))];
    }
}
