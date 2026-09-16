using MailServer.Domain.Enums;

namespace MailServer.Domain.ValueObjects;

/// <summary>
/// A parsed DMARC policy record: <c>v=DMARC1</c> followed by <c>;</c>-separated tags, published
/// as a TXT record at <c>_dmarc.{domain}</c>. RFC 7489 §6.3/§6.4.
/// </summary>
/// <remarks>
/// <para>
/// Purely a parser, like <see cref="SpfRecord"/>: fetching the TXT record, walking the
/// organizational-domain fallback chain (RFC 7489 §6.6.3), and computing alignment against a
/// message's SPF/DKIM results are all
/// <c>MailServer.Infrastructure.Dmarc.DmarcEvaluator</c>'s job.
/// </para>
/// <para>
/// <c>rua=</c>/<c>ruf=</c>/<c>fo=</c>/<c>ri=</c> and any other tag are recognised only enough not
/// to trip a syntax error, then ignored outright — aggregate and failure reporting are out of
/// scope for this milestone (see the addendum recording that scope decision). Nothing in this
/// server ever generates or sends a report, so parsing those tags into structured data would be
/// dead code.
/// </para>
/// </remarks>
public sealed class DmarcRecord
{
    private DmarcRecord(
        DmarcPolicy policy, DmarcPolicy? subdomainPolicy, int percentage, AlignmentMode dkimAlignment, AlignmentMode spfAlignment)
    {
        Policy = policy;
        SubdomainPolicy = subdomainPolicy ?? policy;
        Percentage = percentage;
        DkimAlignment = dkimAlignment;
        SpfAlignment = spfAlignment;
    }

    /// <summary>The requested handling for mail claiming this exact domain (<c>p=</c>). Required.</summary>
    public DmarcPolicy Policy { get; }

    /// <summary>
    /// The requested handling for mail claiming a subdomain of this domain (<c>sp=</c>). Falls
    /// back to <see cref="Policy"/> when the record carries no <c>sp=</c> tag of its own — RFC
    /// 7489 §6.3: "the policy MUST be applied by a Mail Receiver as if it were the value of 'p'".
    /// </summary>
    public DmarcPolicy SubdomainPolicy { get; }

    /// <summary>
    /// The percentage of failing messages the policy applies to (<c>pct=</c>), 0-100. Defaults to
    /// 100 when absent. RFC 7489 §6.3 — sampling exists so a domain owner can ramp up enforcement
    /// gradually rather than switching every failing message to quarantine/reject at once.
    /// </summary>
    public int Percentage { get; }

    /// <summary>DKIM alignment mode (<c>adkim=</c>). Defaults to relaxed.</summary>
    public AlignmentMode DkimAlignment { get; }

    /// <summary>SPF alignment mode (<c>aspf=</c>). Defaults to relaxed.</summary>
    public AlignmentMode SpfAlignment { get; }

    /// <summary>Parses one candidate DMARC record's text (a single TXT record's concatenated content).</summary>
    public static bool TryParse(string? recordText, out DmarcRecord? record, out string? error)
    {
        record = null;
        error = null;

        if (string.IsNullOrWhiteSpace(recordText))
        {
            error = "the record is empty.";
            return false;
        }

        string[] tagSpecs = recordText.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (tagSpecs.Length == 0 || !TryParseTag(tagSpecs[0], out string firstName, out string firstValue))
        {
            error = "the record does not begin with a valid tag.";
            return false;
        }

        if (!string.Equals(firstName, "v", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(firstValue, "DMARC1", StringComparison.Ordinal))
        {
            error = "the record does not begin with the exact tag 'v=DMARC1'.";
            return false;
        }

        DmarcPolicy? policy = null;
        DmarcPolicy? subdomainPolicy = null;
        int percentage = 100;
        AlignmentMode dkimAlignment = AlignmentMode.Relaxed;
        AlignmentMode spfAlignment = AlignmentMode.Relaxed;

        // RFC 7489 borrows RFC 6376 §3.2's tag-list syntax, under which a tag name occurring
        // more than once makes the entire record invalid - never "last one wins" (see
        // DkimSignatureTags.TryParse's identical rule for the same syntax).
        HashSet<string> seenTags = new(StringComparer.OrdinalIgnoreCase) { firstName };

        for (int i = 1; i < tagSpecs.Length; i++)
        {
            if (!TryParseTag(tagSpecs[i], out string name, out string value))
            {
                error = $"'{tagSpecs[i]}' is not a valid tag-spec.";
                return false;
            }

            if (!seenTags.Add(name))
            {
                error = $"tag '{name}' appears more than once.";
                return false;
            }

            switch (name.ToLowerInvariant())
            {
                case "p":
                    if (!TryParsePolicy(value, out DmarcPolicy p))
                    {
                        error = $"'{value}' is not a valid 'p' value.";
                        return false;
                    }

                    policy = p;
                    break;

                case "sp":
                    if (!TryParsePolicy(value, out DmarcPolicy sp))
                    {
                        error = $"'{value}' is not a valid 'sp' value.";
                        return false;
                    }

                    subdomainPolicy = sp;
                    break;

                case "pct":
                    if (!int.TryParse(value, out percentage) || percentage < 0 || percentage > 100)
                    {
                        error = $"'{value}' is not a valid 'pct' value; it must be an integer from 0 to 100.";
                        return false;
                    }

                    break;

                case "adkim":
                    if (!TryParseAlignmentMode(value, out dkimAlignment))
                    {
                        error = $"'{value}' is not a valid 'adkim' value.";
                        return false;
                    }

                    break;

                case "aspf":
                    if (!TryParseAlignmentMode(value, out spfAlignment))
                    {
                        error = $"'{value}' is not a valid 'aspf' value.";
                        return false;
                    }

                    break;

                default:
                    // rua=, ruf=, fo=, ri=, and anything unrecognised: RFC 7489 §6.4 requires
                    // unknown tags to be ignored, not treated as a syntax error.
                    break;
            }
        }

        if (policy is null)
        {
            // RFC 7489 §6.6.3: a record with no "p" tag, or an invalid one, must be discarded
            // entirely - there is no DMARC policy to apply, not a policy of "none".
            error = "the record has no 'p' tag.";
            return false;
        }

        record = new DmarcRecord(policy.Value, subdomainPolicy, percentage, dkimAlignment, spfAlignment);
        return true;
    }

    private static bool TryParseTag(string tagSpec, out string name, out string value)
    {
        name = string.Empty;
        value = string.Empty;

        int eqIndex = tagSpec.IndexOf('=');

        if (eqIndex <= 0 || eqIndex == tagSpec.Length - 1)
        {
            return false;
        }

        name = tagSpec[..eqIndex].TrimEnd();
        value = tagSpec[(eqIndex + 1)..].TrimStart();
        return name.Length > 0 && value.Length > 0;
    }

    private static bool TryParsePolicy(string value, out DmarcPolicy policy)
    {
        switch (value.ToLowerInvariant())
        {
            case "none":
                policy = DmarcPolicy.None;
                return true;
            case "quarantine":
                policy = DmarcPolicy.Quarantine;
                return true;
            case "reject":
                policy = DmarcPolicy.Reject;
                return true;
            default:
                policy = default;
                return false;
        }
    }

    private static bool TryParseAlignmentMode(string value, out AlignmentMode mode)
    {
        switch (value.ToLowerInvariant())
        {
            case "r":
                mode = AlignmentMode.Relaxed;
                return true;
            case "s":
                mode = AlignmentMode.Strict;
                return true;
            default:
                mode = default;
                return false;
        }
    }
}
