using MailServer.Domain.Deliverability;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Deliverability;

/// <summary>What a selector's key turned out to be, when it was looked up.</summary>
public enum AnalysedKeyState
{
    /// <summary>No lookup was made.</summary>
    Unknown = 0,

    /// <summary>A usable key is published at the selector.</summary>
    Published = 1,

    /// <summary>The selector's name resolves to nothing.</summary>
    NotPublished = 2,

    /// <summary>
    /// The key is published and explicitly withdrawn.
    /// </summary>
    /// <remarks>
    /// RFC 6376 §3.6.1 gives <c>p=</c> with an empty value that meaning. Its own state because
    /// the cause differs entirely from a missing record: somebody retired this selector, and
    /// something is still signing with it.
    /// </remarks>
    Revoked = 3,

    /// <summary>Something is published there, but it is not a key this could use.</summary>
    Unusable = 4,

    /// <summary>The lookup did not answer, so nothing was established either way.</summary>
    LookupFailed = 5,
}

/// <summary>One signature's selector, looked up.</summary>
/// <param name="Selector">The <c>s=</c> tag.</param>
/// <param name="Domain">The <c>d=</c> tag.</param>
/// <param name="State">What the lookup found.</param>
/// <param name="KeyBits">The RSA modulus size, when one could be measured.</param>
/// <param name="Diagnostic">What went wrong, when something did.</param>
public sealed record AnalysedKey(
    string Selector,
    string Domain,
    AnalysedKeyState State,
    int? KeyBits,
    string? Diagnostic);

/// <summary>
/// What this server established for itself about a pasted header block.
/// </summary>
/// <param name="Spf">The SPF result, evaluated here rather than read from the message.</param>
/// <param name="SpfDomain">The domain SPF was checked for — the <c>Return-Path</c>'s.</param>
/// <param name="SpfAddress">The address SPF was checked against.</param>
/// <param name="SpfAddressFromTrace">
/// True when <paramref name="SpfAddress"/> came out of the pasted trace chain rather than being
/// supplied. <b>An address from the chain is only as trustworthy as the hop that wrote it.</b>
/// </param>
/// <param name="SpfDiagnostic">The evaluator's own explanation.</param>
/// <param name="Keys">Each signature's selector, looked up.</param>
/// <param name="DmarcRecordText">The <c>_dmarc</c> record found for the From domain, if any.</param>
/// <param name="DmarcPolicy">Its <c>p=</c>, when it parsed.</param>
/// <param name="SpfAligned">
/// Whether the SPF-authenticated domain aligns with <c>From</c> under the record's
/// <c>aspf=</c> mode. RFC 7489 §3.1.2.
/// </param>
/// <param name="DkimCouldAlign">
/// Whether some signature's <c>d=</c> aligns with <c>From</c> under <c>adkim=</c> <i>and</i> its
/// key is published. <b>Not "DKIM passes"</b> — see the remarks on
/// <see cref="IHeaderAnalysisService"/>.
/// </param>
public sealed record HeaderAuthentication(
    SpfResult? Spf,
    DomainName? SpfDomain,
    IpAddressValue? SpfAddress,
    bool SpfAddressFromTrace,
    string? SpfDiagnostic,
    IReadOnlyList<AnalysedKey> Keys,
    string? DmarcRecordText,
    DmarcPolicy? DmarcPolicy,
    bool SpfAligned,
    bool DkimCouldAlign);

/// <summary>A pasted header block, read and then checked against DNS.</summary>
/// <param name="Headers">What the block says.</param>
/// <param name="Authentication">What this server established about it.</param>
/// <param name="Observations">
/// <see cref="HeaderAnalysis.Observations"/> plus the ones only a lookup can produce.
/// </param>
public sealed record AnalysedHeaders(
    HeaderAnalysis Headers,
    HeaderAuthentication Authentication,
    IReadOnlyList<HeaderObservation> Observations);

/// <summary>
/// Reads a pasted header block and checks what it claims against DNS.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every verdict here is this server's own.</b> Nothing reads an authentication result off
/// the message — <c>docs/DMARC.md</c>: "Trusting an attacker-supplied
/// <c>Authentication-Results: dmarc=pass</c> header is a complete authentication bypass, and it
/// is trivially easy to do by accident."
/// </para>
/// <para>
/// <b>DKIM is never reported as passing, because a header block cannot show that.</b> RFC 6376
/// §3.7 computes the body hash over the body, and there is no body in a paste. What can be
/// established is whether the selector's key is published and usable and whether its <c>d=</c>
/// aligns — which is to say, whether the signature could have helped. A signature over a
/// modified body would look identical here, so <see cref="HeaderAuthentication.DkimCouldAlign"/>
/// is named for what it means.
/// </para>
/// <para>
/// <b>SPF is checked against the <c>Return-Path</c> domain, not <c>From</c>.</b> RFC 7208 §2.2:
/// "Without explicit approval of the publishing ADMD, checking other identities against SPF
/// version 1 records is NOT RECOMMENDED because there are cases that are known to give incorrect
/// results. For example, almost all mailing lists rewrite the 'MAIL FROM' identity […] but some
/// do not change any other identities in the message." Checking <c>From</c> would be exactly
/// that mistake, and it is the one that makes a forwarded message look forged.
/// </para>
/// </remarks>
public interface IHeaderAnalysisService
{
    /// <summary>Analyses a pasted header block.</summary>
    /// <param name="text">The headers, as pasted.</param>
    /// <param name="clientAddress">
    /// The address the message was received from, when the operator knows it. Null takes the
    /// topmost trace hop's observed address instead, which the result flags.
    /// </param>
    /// <param name="cancellationToken">Cancellation.</param>
    Task<AnalysedHeaders> AnalyseAsync(
        string? text,
        IpAddressValue? clientAddress,
        CancellationToken cancellationToken);
}
