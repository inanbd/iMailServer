namespace MailServer.Domain.Enums;

/// <summary>
/// The services a certificate binding applies to.
/// </summary>
/// <remarks>
/// <para>
/// A <c>[Flags]</c> enum because one certificate almost always covers several services: an
/// operator issues one certificate for <c>mail.example.com</c> and uses it for SMTP, IMAP and
/// the HTTPS endpoint. Modelling that as three rows would make "renew the certificate" three
/// operations that could partially fail.
/// </para>
/// <para>
/// Separate bindings per purpose remain possible, which is what an operator with a dedicated
/// submission hostname needs.
/// </para>
/// </remarks>
[Flags]
public enum CertificatePurpose
{
    None = 0,

    /// <summary>Inbound SMTP on port 25 (STARTTLS).</summary>
    SmtpInbound = 1,

    /// <summary>Authenticated submission on 587 (STARTTLS) and 465 (implicit).</summary>
    SmtpSubmission = 2,

    /// <summary>IMAP on 993, and POP3 on 995 where enabled.</summary>
    MailboxAccess = 4,

    /// <summary>The HTTPS endpoint, including ACME HTTP-01 responses and MTA-STS policy hosting.</summary>
    Https = 8,

    /// <summary>Every service. The normal choice for a single-hostname installation.</summary>
    All = SmtpInbound | SmtpSubmission | MailboxAccess | Https,
}
