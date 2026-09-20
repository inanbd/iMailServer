using System.Globalization;
using System.Text;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Deliverability;

/// <summary>The record types this server ever asks an operator to publish.</summary>
public enum DnsRecordKind
{
    /// <summary>An IPv4 address for the mail host.</summary>
    A = 0,

    /// <summary>An IPv6 address for the mail host.</summary>
    Aaaa = 1,

    /// <summary>Where mail for the domain is delivered.</summary>
    Mx = 2,

    /// <summary>Everything policy-shaped: SPF, DKIM, DMARC, MTA-STS, TLS-RPT.</summary>
    Txt = 3,

    /// <summary>The reverse name for a sending address. Never in the domain's own zone.</summary>
    Ptr = 4,
}

/// <summary>Whose zone a record belongs in.</summary>
/// <remarks>
/// The distinction exists because getting it wrong is the single most common reason a
/// self-hosted server cannot deliver to a large receiver — see <c>docs/DNS.md</c>. An operator
/// handed one undifferentiated list will try to publish the <c>PTR</c> in their own zone, find
/// that it has no effect, and conclude the advice was wrong.
/// </remarks>
public enum DnsRecordPlacement
{
    /// <summary>Publish it in the domain's own zone.</summary>
    OwnZone = 0,

    /// <summary>
    /// Ask whoever owns the IP address — hosting provider, datacentre, ISP.
    /// </summary>
    IpOwner = 1,
}

/// <summary>
/// One record an operator should publish, with the reason they are being asked for it.
/// </summary>
/// <param name="Name">
/// The record's fully qualified owner name, without a trailing dot. Fully qualified rather than
/// relative because a zone file's <c>@</c> and bare labels mean different things in different
/// providers' web forms, and a name that is already complete cannot be pasted wrongly.
/// </param>
/// <param name="Kind">The record type.</param>
/// <param name="Values">
/// The record's data. More than one entry means one of two different things depending on
/// <paramref name="Kind"/>: for <see cref="DnsRecordKind.Txt"/> these are the character-strings
/// of a single record and are concatenated by the reader (see
/// <see cref="DnsRecordPlan.SplitTxt"/>); for anything else they are separate records with the
/// same owner name.
/// </param>
/// <param name="Placement">Whose zone it belongs in.</param>
/// <param name="Purpose">What breaks without it, in the operator's terms.</param>
/// <param name="IsOptional">
/// True for a record that improves a working configuration rather than one that is required for
/// mail to flow. Ordering these after the required ones is what keeps an operator from spending
/// their attention in the wrong place.
/// </param>
public sealed record DnsRecordAdvice(
    string Name,
    DnsRecordKind Kind,
    IReadOnlyList<string> Values,
    DnsRecordPlacement Placement,
    string Purpose,
    bool IsOptional = false);

/// <summary>Something true about this plan that is not itself a record.</summary>
/// <param name="Subject">What it is about, for grouping in a UI.</param>
/// <param name="Text">The caveat, in full sentences.</param>
public sealed record DnsPlanCaveat(string Subject, string Text);

/// <summary>Everything an operator should publish for one domain, and everything to know first.</summary>
/// <param name="Records">In the order they should be worked through.</param>
/// <param name="Caveats">Obligations that no record in this plan discharges.</param>
public sealed record DnsZonePlan(
    IReadOnlyList<DnsRecordAdvice> Records,
    IReadOnlyList<DnsPlanCaveat> Caveats);

/// <summary>The published half of a DKIM key, as the plan needs it.</summary>
/// <param name="Selector">The selector the key is published under.</param>
/// <param name="Algorithm">Decides the <c>k=</c> tag.</param>
/// <param name="PublicKeyBase64">The SubjectPublicKeyInfo, base64, exactly as stored.</param>
public sealed record DkimKeyPublication(
    DkimSelector Selector,
    DkimKeyAlgorithm Algorithm,
    string PublicKeyBase64);

/// <summary>What the planner needs to know to write a zone's worth of advice.</summary>
/// <remarks>
/// Everything here is something this server already knows about itself, except the two reporting
/// addresses and the MTA-STS decision — which are choices, not facts, and so are the operator's
/// to make.
/// </remarks>
/// <param name="Domain">The domain that sends and receives mail.</param>
/// <param name="MailHost">This server's own name, which the MX points at.</param>
/// <param name="HostAddresses">Every address the mail host answers on and sends from.</param>
/// <param name="Dkim">The key to publish, or null when none has been generated yet.</param>
/// <param name="DmarcReportAddress">Where aggregate DMARC reports should go, or null for none.</param>
/// <param name="TlsReportAddress">Where TLS-RPT reports should go, or null to skip TLS-RPT.</param>
/// <param name="MtaStsId">
/// The policy id to advertise, or null to skip MTA-STS. RFC 8461 §3.1 constrains it to
/// <c>1*32(ALPHA / DIGIT)</c>; one that breaks that earns a caveat rather than a silent record
/// no sender will read.
/// </param>
/// <param name="PublicSuffixes">
/// Used only to decide whether a reporting address is external in RFC 7489 §7.1's sense. Null
/// means "do not guess", and the caveat is then raised on any differing domain.
/// </param>
public sealed record DnsPlanRequest(
    DomainName Domain,
    DomainName MailHost,
    IReadOnlyList<IpAddressValue> HostAddresses,
    DkimKeyPublication? Dkim = null,
    EmailAddress? DmarcReportAddress = null,
    EmailAddress? TlsReportAddress = null,
    string? MtaStsId = null,
    PublicSuffixList? PublicSuffixes = null);

/// <summary>
/// Writes the records a domain needs in order to send mail that is accepted.
/// </summary>
/// <remarks>
/// <para>
/// The companion to the readiness report: the report says what is wrong, and this says what to
/// publish. They are deliberately separate — the report reads DNS and grades it, this reads
/// nothing at all — so that an operator with no records yet has something to act on, and so that
/// this class is a pure function of what the server knows about itself.
/// </para>
/// <para>
/// <b>It never proposes a record the report would then complain about.</b> The one place the two
/// could disagree is <c>p=none</c>, which
/// <c>AuthenticationChecks</c> warns about and this proposes: they agree, because that check's
/// own text says it is "the right setting while you are reading reports" and its remedy is the
/// next step rather than a different starting point. The purpose text here says the same thing,
/// so an operator who follows this plan and then runs the report is not told they were misled.
/// </para>
/// <para>
/// <b>The plan is advice, not an intention.</b> Nothing here writes to DNS, and this product has
/// no credentials to any registrar. Publishing is the operator's act, which is also why every
/// record carries a purpose: a list of opaque strings to paste is a list nobody audits.
/// </para>
/// </remarks>
public static class DnsRecordPlan
{
    /// <summary>
    /// The longest a single TXT character-string may be.
    /// </summary>
    /// <remarks>
    /// RFC 1035 §3.3.14's <c>character-string</c> is a length octet followed by that many
    /// octets, so 255 is the ceiling and it is a limit on <b>octets</b> rather than characters.
    /// A 2048-bit RSA public key in base64 is comfortably past it, which is why
    /// <see cref="SplitTxt"/> exists at all: an operator who pastes a 392-character key into a
    /// provider's single-string TXT field gets either a truncated record or a refusal, and the
    /// truncation is the dangerous one because it publishes a key that parses and verifies
    /// nothing.
    /// </remarks>
    public const int MaxTxtStringOctets = 255;

    /// <summary>
    /// Splits one TXT value into the character-strings it must be published as.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Split anywhere, because every consumer of these records concatenates with nothing in
    /// between.</b> RFC 6376 §3.6.2.2 for DKIM: "Strings in a TXT RR MUST be concatenated
    /// together before use with no intervening whitespace." RFC 7208 §3.3 for SPF: "If a
    /// published record contains multiple character-strings, then the record MUST be treated as
    /// if those strings are concatenated together without adding spaces." So the split is free
    /// of meaning and needs no token awareness — which is the only reason a purely positional
    /// split is safe here.
    /// </para>
    /// <para>
    /// <b>Never in the middle of a character.</b> The limit counts octets, and cutting a
    /// multi-byte UTF-8 sequence in half would produce two strings that concatenate back to
    /// something a resolver may reject and a reader will certainly misread. Splitting on rune
    /// boundaries costs nothing for the ASCII these records are made of and makes the
    /// non-ASCII case wrong-free rather than unconsidered.
    /// </para>
    /// </remarks>
    /// <param name="value">The whole value, as it will read once concatenated.</param>
    /// <returns>One entry for a value that fits; several, in order, for one that does not.</returns>
    public static IReadOnlyList<string> SplitTxt(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (Encoding.UTF8.GetByteCount(value) <= MaxTxtStringOctets)
        {
            return [value];
        }

        List<string> parts = [];
        StringBuilder current = new();
        int octets = 0;

        foreach (Rune rune in value.EnumerateRunes())
        {
            int width = rune.Utf8SequenceLength;

            if (octets + width > MaxTxtStringOctets)
            {
                parts.Add(current.ToString());
                current.Clear();
                octets = 0;
            }

            current.Append(rune);
            octets += width;
        }

        if (current.Length > 0)
        {
            parts.Add(current.ToString());
        }

        return parts;
    }

    /// <summary>
    /// The preference this server proposes for the MX record.
    /// </summary>
    /// <remarks>
    /// Ten rather than zero or one, because RFC 5321 §5.1 ranks by preference and leaves room
    /// between values for a second exchanger to be added later without renumbering the first.
    /// An operator who starts at 0 has to edit a working record to add a backup.
    /// </remarks>
    public const int MxPreference = 10;

    /// <summary>Writes the plan.</summary>
    public static DnsZonePlan Create(DnsPlanRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        List<DnsRecordAdvice> records = [];
        List<DnsPlanCaveat> caveats = [];

        AddHostAddresses(request, records, caveats);
        AddMailExchanger(request, records, caveats);
        AddSpf(request, records);
        AddDkim(request, records, caveats);
        AddDmarc(request, records, caveats);
        AddMtaSts(request, records, caveats);
        AddTlsReporting(request, records);
        AddReverse(request, records, caveats);

        return new DnsZonePlan(records, caveats);
    }

    // -----------------------------------------------------------------------------------------
    // The host itself.
    // -----------------------------------------------------------------------------------------

    private static void AddHostAddresses(
        DnsPlanRequest request,
        List<DnsRecordAdvice> records,
        List<DnsPlanCaveat> caveats)
    {
        string[] v4 = [.. request.HostAddresses.Where(a => a.IsIpV4).Select(a => a.Value)];
        string[] v6 = [.. request.HostAddresses.Where(a => a.IsIpV6).Select(a => a.Value)];

        if (v4.Length > 0)
        {
            records.Add(new DnsRecordAdvice(
                request.MailHost.Value,
                DnsRecordKind.A,
                v4,
                DnsRecordPlacement.OwnZone,
                "Resolves this server's name. Everything else here names the host rather than " +
                "an address, so nothing works until this does."));
        }

        if (v6.Length > 0)
        {
            records.Add(new DnsRecordAdvice(
                request.MailHost.Value,
                DnsRecordKind.Aaaa,
                v6,
                DnsRecordPlacement.OwnZone,
                "Resolves this server's name over IPv6. Publish it only if the server really " +
                "does send from this address: a receiver that connects over IPv6 applies its " +
                "IPv6 reputation and its own reverse-DNS rules, which are usually stricter."));
        }

        if (request.HostAddresses.Count == 0)
        {
            caveats.Add(new DnsPlanCaveat(
                "Addresses",
                "This server does not know a public address for itself, so there is no A or " +
                "AAAA record in this plan and no address to put in SPF. Everything below still " +
                "names the host, so publish the address record first."));

            return;
        }

        if (request.HostAddresses.Any(a => a.IsPrivate))
        {
            caveats.Add(new DnsPlanCaveat(
                "Addresses",
                "One of this server's addresses is in private space. A private address in " +
                "public DNS resolves to nothing usable from the Internet, and in SPF it " +
                "authorises nobody. Publish the address the world actually reaches this " +
                "server on."));
        }
    }

    private static void AddMailExchanger(
        DnsPlanRequest request,
        List<DnsRecordAdvice> records,
        List<DnsPlanCaveat> caveats)
    {
        records.Add(new DnsRecordAdvice(
            request.Domain.Value,
            DnsRecordKind.Mx,
            [$"{MxPreference} {request.MailHost.Value}."],
            DnsRecordPlacement.OwnZone,
            "Tells the world where to deliver mail for this domain."));

        caveats.Add(new DnsPlanCaveat(
            "Mail exchanger",
            $"{request.MailHost.Value} must be a name with address records of its own, never a " +
            "CNAME. RFC 2181 §10.3: \"The domain name used as the value of a NS resource " +
            "record, or part of the value of a MX resource record must not be an alias.\" An " +
            "alias here is the kind of mistake that works with some senders and not others."));
    }

    // -----------------------------------------------------------------------------------------
    // Authentication.
    // -----------------------------------------------------------------------------------------

    private static void AddSpf(DnsPlanRequest request, List<DnsRecordAdvice> records)
    {
        List<string> mechanisms = ["v=spf1", "mx"];

        foreach (IpAddressValue address in request.HostAddresses)
        {
            mechanisms.Add(address.IsIpV4 ? $"ip4:{address.Value}" : $"ip6:{address.Value}");
        }

        mechanisms.Add("-all");

        records.Add(new DnsRecordAdvice(
            request.Domain.Value,
            DnsRecordKind.Txt,
            SplitTxt(string.Join(' ', mechanisms)),
            DnsRecordPlacement.OwnZone,
            "Says which hosts may send mail as this domain. Publish exactly one SPF record: a " +
            "domain with two gets a permanent error from every receiver, which several treat " +
            "as a failure — worse than having none. The mx mechanism costs one of RFC 7208's " +
            "ten lookups and can be dropped once every sending address is listed here."));
    }

    private static void AddDkim(
        DnsPlanRequest request,
        List<DnsRecordAdvice> records,
        List<DnsPlanCaveat> caveats)
    {
        if (request.Dkim is not { } dkim)
        {
            caveats.Add(new DnsPlanCaveat(
                "DKIM",
                "No DKIM key has been generated for this domain yet, so this plan has no key " +
                "record. Generate one first: SPF alone breaks on every forwarded message, " +
                "because forwarding changes the envelope sender and leaves the signature " +
                "intact."));

            return;
        }

        string algorithm = dkim.Algorithm switch
        {
            DkimKeyAlgorithm.Ed25519Sha256 => "ed25519",
            _ => "rsa",
        };

        records.Add(new DnsRecordAdvice(
            $"{dkim.Selector.Value}.{DkimSelector.DomainKeySubdomain}.{request.Domain.Value}",
            DnsRecordKind.Txt,
            SplitTxt($"v=DKIM1; k={algorithm}; p={dkim.PublicKeyBase64}"),
            DnsRecordPlacement.OwnZone,
            "Publishes the public half of the key this server signs with. Until it resolves, " +
            "every signature this server writes fails at the receiver."));

        caveats.Add(new DnsPlanCaveat(
            "DKIM",
            "The key is longer than a single TXT string may be, so it is given here as several " +
            "strings of one record. Some providers take them in one field and split them for " +
            "you; some want them quoted and separated; a few silently truncate. Read the " +
            "record back before trusting it — a truncated key parses and verifies nothing."));
    }

    private static void AddDmarc(
        DnsPlanRequest request,
        List<DnsRecordAdvice> records,
        List<DnsPlanCaveat> caveats)
    {
        string policy = "v=DMARC1; p=none";

        if (request.DmarcReportAddress is { } reports)
        {
            policy += $"; rua=mailto:{reports.Value}";
        }

        records.Add(new DnsRecordAdvice(
            $"_dmarc.{request.Domain.Value}",
            DnsRecordKind.Txt,
            SplitTxt(policy),
            DnsRecordPlacement.OwnZone,
            "Tells receivers what to do with mail that fails both SPF and DKIM, and where to " +
            "send reports. It starts at p=none, which asks them to do nothing: that is the " +
            "right setting while you read the first reports, and it protects nobody. Move to " +
            "p=quarantine and then p=reject once the reports show your own mail passing."));

        if (request.DmarcReportAddress is null)
        {
            caveats.Add(new DnsPlanCaveat(
                "DMARC",
                "No reporting address was given, so this record asks for no reports. A DMARC " +
                "record without rua= is a policy published blind: there is no way to see " +
                "whether your own mail passes before you tighten it."));

            return;
        }

        AddExternalReportingCaveat(
            request,
            request.DmarcReportAddress,
            caveats,
            "DMARC");
    }

    /// <summary>
    /// Warns when reports are addressed outside the domain, and names the record that fixes it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 7489 §7.1 makes this an authorisation, not a formality: a receiver that finds a
    /// reporting address outside the policy's own organizational domain must query
    /// <c>{policy-domain}._report._dmarc.{reporting-domain}</c> and "Where the above algorithm
    /// fails to confirm that the external reporting was authorized by the Report Receiver, the
    /// URI MUST be ignored". So an operator who points <c>rua=</c> at a third-party analytics
    /// service and publishes nothing else gets silence, and no error anywhere to explain it.
    /// </para>
    /// <para>
    /// <b>Compared by organizational domain, not by name.</b> §7.1 says "the Organizational
    /// Domain at which that record was discovered is not identical to the Organizational Domain
    /// of the host part", so <c>rua=mailto:dmarc@example.com</c> on <c>mail.example.com</c>
    /// needs no such record. Comparing the literal names would raise this caveat on the most
    /// ordinary configuration there is. Without a suffix list to ask, the caveat is raised on
    /// any difference: telling an operator to publish a record they turn out not to need costs
    /// them a minute, and the reverse costs them every report.
    /// </para>
    /// </remarks>
    private static void AddExternalReportingCaveat(
        DnsPlanRequest request,
        EmailAddress reports,
        List<DnsPlanCaveat> caveats,
        string subject)
    {
        DomainName reportDomain = reports.Domain;

        if (IsSameOrganization(request.Domain, reportDomain, request.PublicSuffixes))
        {
            return;
        }

        caveats.Add(new DnsPlanCaveat(
            subject,
            $"Reports are addressed to {reportDomain.Value}, which is outside " +
            $"{request.Domain.Value}. RFC 7489 §7.1 makes that an arrangement the receiving " +
            "domain has to confirm, so whoever runs " +
            $"{reportDomain.Value} must publish a TXT record at " +
            $"{request.Domain.Value}._report._dmarc.{reportDomain.Value} containing at least " +
            "v=DMARC1. Until they do, reports are not sent and nothing reports that they " +
            "were not."));
    }

    private static bool IsSameOrganization(
        DomainName domain,
        DomainName other,
        PublicSuffixList? suffixes)
    {
        if (domain.Equals(other))
        {
            return true;
        }

        return suffixes is not null &&
            suffixes.GetOrganizationalDomain(domain)
                .Equals(suffixes.GetOrganizationalDomain(other));
    }

    // -----------------------------------------------------------------------------------------
    // Transport policy.
    // -----------------------------------------------------------------------------------------

    private static void AddMtaSts(
        DnsPlanRequest request,
        List<DnsRecordAdvice> records,
        List<DnsPlanCaveat> caveats)
    {
        if (request.MtaStsId is not { Length: > 0 } id)
        {
            return;
        }

        if (!IsValidStsId(id))
        {
            caveats.Add(new DnsPlanCaveat(
                "MTA-STS",
                $"The policy id \"{id}\" is not one RFC 8461 §3.1 allows, so no MTA-STS record " +
                "is in this plan. Its grammar is id= followed by one to thirty-two letters and " +
                "digits and nothing else — no punctuation, no colons. A timestamp such as " +
                "20260920T104500 fits; the same timestamp with separators does not."));

            return;
        }

        records.Add(new DnsRecordAdvice(
            $"_mta-sts.{request.Domain.Value}",
            DnsRecordKind.Txt,
            SplitTxt($"v=STSv1; id={id};"),
            DnsRecordPlacement.OwnZone,
            "Tells senders that a TLS policy exists and when it last changed. Change the id " +
            "every time the policy file changes: senders re-fetch the file only when this " +
            "value differs from the one they cached.",
            IsOptional: true));

        records.Add(new DnsRecordAdvice(
            $"mta-sts.{request.Domain.Value}",
            DnsRecordKind.A,
            [.. request.HostAddresses.Where(a => a.IsIpV4).Select(a => a.Value)],
            DnsRecordPlacement.OwnZone,
            "The policy is served over HTTPS from this name, so it needs to resolve. Point it " +
            "at whatever host serves the policy file; this server's own address is only a " +
            "sensible default if it is also the web server.",
            IsOptional: true));

        caveats.Add(new DnsPlanCaveat(
            "MTA-STS",
            "The TXT record on its own does nothing. RFC 8461 §3.2 has senders fetch the policy " +
            $"from https://mta-sts.{request.Domain.Value}/.well-known/mta-sts.txt over HTTPS " +
            "with a certificate that is valid for that name, served as text/plain. A record " +
            "that advertises a policy which cannot be fetched leaves senders no worse off than " +
            "no record at all, but it also buys nothing."));
    }

    /// <summary>RFC 8461 §3.1: <c>sts-id = %s"id=" 1*32(ALPHA / DIGIT)</c>.</summary>
    private static bool IsValidStsId(string id) =>
        id.Length <= 32 && id.All(char.IsAsciiLetterOrDigit);

    private static void AddTlsReporting(DnsPlanRequest request, List<DnsRecordAdvice> records)
    {
        if (request.TlsReportAddress is not { } reports)
        {
            return;
        }

        records.Add(new DnsRecordAdvice(
            $"_smtp._tls.{request.Domain.Value}",
            DnsRecordKind.Txt,
            SplitTxt($"v=TLSRPTv1; rua=mailto:{reports.Value}"),
            DnsRecordPlacement.OwnZone,
            "Asks senders to report TLS failures they had delivering to this domain. It is the " +
            "only way to learn that a certificate renewal broke delivery for somebody, because " +
            "the sender retries quietly and then gives up quietly.",
            IsOptional: true));
    }

    // -----------------------------------------------------------------------------------------
    // The one record that is not the operator's to publish.
    // -----------------------------------------------------------------------------------------

    private static void AddReverse(
        DnsPlanRequest request,
        List<DnsRecordAdvice> records,
        List<DnsPlanCaveat> caveats)
    {
        if (request.HostAddresses.Count == 0)
        {
            return;
        }

        foreach (IpAddressValue address in request.HostAddresses)
        {
            records.Add(new DnsRecordAdvice(
                address.ToReverseDnsName(),
                DnsRecordKind.Ptr,
                [$"{request.MailHost.Value}."],
                DnsRecordPlacement.IpOwner,
                $"The reverse name for {address.Value}. Major receivers refuse or spam-folder " +
                "mail from an address whose reverse name does not resolve back to the same " +
                "address, and this is the single most common reason a self-hosted server " +
                "cannot deliver to a large provider."));
        }

        caveats.Add(new DnsPlanCaveat(
            "Reverse DNS",
            "The reverse records above are not yours to publish. They live in the address " +
            "owner's zone — your hosting provider, datacentre or ISP — and no amount of " +
            "correct SPF, DKIM or DMARC compensates for their absence. If your provider will " +
            "not set one, you cannot run a public mail server on that address."));
    }

    /// <summary>
    /// Renders a plan as zone-file lines, for an operator who would rather paste than click.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Owner names are fully qualified and end with a dot, so the text means the same thing
    /// wherever it is pasted: a relative name in a zone file is completed with <c>$ORIGIN</c>,
    /// and a plan pasted under the wrong origin produces <c>_dmarc.example.com.example.com</c>
    /// — which resolves, answers nothing, and looks right at a glance.
    /// </para>
    /// <para>
    /// Records the operator cannot publish are rendered as comments rather than left out. An
    /// operator pasting this into their zone must not accidentally publish a <c>PTR</c> into
    /// their own zone, and must not be left thinking reverse DNS was something this plan
    /// forgot.
    /// </para>
    /// </remarks>
    public static string ToZoneText(DnsZonePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        StringBuilder text = new();

        foreach (DnsRecordAdvice record in plan.Records)
        {
            string prefix = record.Placement == DnsRecordPlacement.OwnZone ? string.Empty : "; ";

            if (record.Kind == DnsRecordKind.Txt)
            {
                string quoted = string.Join(' ', record.Values.Select(Quote));

                text.Append(prefix)
                    .Append(CultureInfo.InvariantCulture, $"{record.Name}. IN TXT {quoted}")
                    .AppendLine();

                continue;
            }

            foreach (string value in record.Values)
            {
                text.Append(prefix)
                    .Append(CultureInfo.InvariantCulture, $"{record.Name}. IN {Kind(record.Kind)} {value}")
                    .AppendLine();
            }
        }

        return text.ToString();
    }

    /// <summary>
    /// Quotes one character-string for a zone file.
    /// </summary>
    /// <remarks>
    /// Backslashes first, then quotes: escaping the quotes first would then have their own
    /// backslashes escaped by the second pass, turning <c>"</c> into <c>\\"</c> and ending the
    /// string a character early. None of the values this planner writes contains either
    /// character today, which is exactly why the order would go unnoticed - so the test that
    /// pins it builds a plan by hand rather than asking for one.
    /// </remarks>
    private static string Quote(string value) =>
        $"\"{value.Replace("\\", "\\\\", StringComparison.Ordinal)
                  .Replace("\"", "\\\"", StringComparison.Ordinal)}\"";

    private static string Kind(DnsRecordKind kind) => kind switch
    {
        DnsRecordKind.A => "A",
        DnsRecordKind.Aaaa => "AAAA",
        DnsRecordKind.Mx => "MX",
        DnsRecordKind.Txt => "TXT",
        DnsRecordKind.Ptr => "PTR",
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Not a record kind this plan writes."),
    };
}
