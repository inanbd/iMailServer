using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Primitives;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// A registration with an ACME certificate authority.
/// </summary>
/// <remarks>
/// <para>
/// <b>This aggregate holds no key material.</b> It carries the account's URL at the CA, the
/// contact address, the terms accepted, and the <i>name</i> of the secret holding the account
/// key — never the key. The same reasoning as <see cref="Certificate"/>: a domain object
/// carrying a private key puts one into every object graph, log line and audit record that
/// touches account metadata.
/// </para>
/// <para>
/// <b>Staging and production are different accounts.</b> An account registered against one
/// directory is meaningless to the other, so the directory is part of this aggregate's identity
/// rather than a setting to flip. Switching to production registers a new account and keeps the
/// staging one, which is what lets an operator go back to testing without losing their trial
/// setup.
/// </para>
/// <para>
/// <b>Losing the account key means losing the ability to revoke</b> certificates issued through
/// it. That is why the key lives in the protected secret store and is included in the material
/// re-wrapped at backup time, and why nothing here ever deletes one.
/// </para>
/// </remarks>
public sealed class AcmeAccount : AggregateRoot<AcmeAccountId>
{
    /// <summary>Rehydration constructor for the persistence layer.</summary>
    /// <remarks>Null guards only; a committed row must always load. See <see cref="MailDomain"/>.</remarks>
    public AcmeAccount(
        AcmeAccountId id,
        AcmeDirectory directory,
        string directoryUrl,
        string? accountUrl,
        string contactEmail,
        string accountKeySecretName,
        string? termsOfServiceAccepted,
        DateTimeOffset? termsAcceptedUtc,
        bool isActive,
        DateTimeOffset createdUtc,
        DateTimeOffset? modifiedUtc) : base(id)
    {
        ArgumentNullException.ThrowIfNull(directoryUrl);
        ArgumentNullException.ThrowIfNull(contactEmail);
        ArgumentNullException.ThrowIfNull(accountKeySecretName);

        Directory = directory;
        DirectoryUrl = directoryUrl;
        AccountUrl = accountUrl;
        ContactEmail = contactEmail;
        AccountKeySecretName = accountKeySecretName;
        TermsOfServiceAccepted = termsOfServiceAccepted;
        TermsAcceptedUtc = termsAcceptedUtc;
        IsActive = isActive;
        CreatedUtc = createdUtc;
        ModifiedUtc = modifiedUtc;
    }

    public AcmeDirectory Directory { get; }

    /// <summary>The directory endpoint this account is registered against.</summary>
    public string DirectoryUrl { get; }

    /// <summary>
    /// The account's URL at the CA, assigned on registration. Null until registered.
    /// </summary>
    /// <remarks>
    /// Its presence is what distinguishes "configured locally" from "known to the CA". A row
    /// with a key and no account URL is a registration that was started and not completed,
    /// which is recoverable; the key is reused and registration retried.
    /// </remarks>
    public string? AccountUrl { get; private set; }

    /// <summary>
    /// Where the CA sends expiry warnings and policy notices.
    /// </summary>
    /// <remarks>
    /// Worth keeping accurate. It is the channel through which an operator learns that renewal
    /// has stopped working, if every local alert has been ignored.
    /// </remarks>
    public string ContactEmail { get; private set; }

    /// <summary>The <i>name</i> of the secret holding the account key — never the key.</summary>
    public string AccountKeySecretName { get; }

    /// <summary>The terms-of-service document that was accepted.</summary>
    /// <remarks>
    /// Recorded by URL rather than as a boolean, because CAs revise their terms and a later
    /// version may need accepting again. "Accepted something, once" cannot answer that; "accepted
    /// LE-SA-v1.8" can.
    /// </remarks>
    public string? TermsOfServiceAccepted { get; private set; }

    public DateTimeOffset? TermsAcceptedUtc { get; private set; }

    /// <summary>False once deactivated at the CA, or superseded by a newer account.</summary>
    public bool IsActive { get; private set; }

    public DateTimeOffset CreatedUtc { get; }

    public DateTimeOffset? ModifiedUtc { get; private set; }

    /// <summary>True when this account can be used to issue.</summary>
    public bool IsUsable => IsActive && AccountUrl is not null;

    /// <summary>
    /// True when certificates from this account are publicly trusted.
    /// </summary>
    /// <remarks>
    /// A staging certificate is a perfectly valid certificate that no browser or MTA trusts,
    /// which is the single most confusing thing about ACME for a new operator. Every surface
    /// that shows one says so.
    /// </remarks>
    public bool IssuesPubliclyTrustedCertificates =>
        Directory is not AcmeDirectory.LetsEncryptStaging;

    /// <summary>Prepares a registration. The key must already be in the secret store.</summary>
    public static AcmeAccount Create(
        AcmeDirectory directory,
        string directoryUrl,
        string contactEmail,
        string accountKeySecretName,
        DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryUrl);
        ArgumentException.ThrowIfNullOrWhiteSpace(contactEmail);
        ArgumentException.ThrowIfNullOrWhiteSpace(accountKeySecretName);

        if (!Uri.TryCreate(directoryUrl, UriKind.Absolute, out Uri? parsed) ||
            parsed.Scheme != Uri.UriSchemeHttps)
        {
            throw new DomainRuleViolationException(
                "acme.directory_url.invalid",
                $"'{directoryUrl}' is not an HTTPS URL. An ACME directory must be fetched over " +
                "HTTPS: the whole protocol's trust rests on the client reaching the real CA, " +
                "and a plaintext directory would let anyone on the path substitute their own.");
        }

        return new AcmeAccount(
            AcmeAccountId.New(),
            directory,
            directoryUrl,
            accountUrl: null,
            contactEmail,
            accountKeySecretName,
            termsOfServiceAccepted: null,
            termsAcceptedUtc: null,
            isActive: true,
            createdUtc: now,
            modifiedUtc: null);
    }

    /// <summary>Records a completed registration.</summary>
    public void MarkRegistered(
        string accountUrl,
        string? termsOfServiceUrl,
        DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountUrl);

        AccountUrl = accountUrl;
        TermsOfServiceAccepted = termsOfServiceUrl;
        TermsAcceptedUtc = termsOfServiceUrl is null ? null : now;
        ModifiedUtc = now;
    }

    public void ChangeContact(string contactEmail, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(contactEmail);

        ContactEmail = contactEmail;
        ModifiedUtc = now;
    }

    /// <summary>
    /// Marks the account unusable for new issuance.
    /// </summary>
    /// <remarks>
    /// The row and its key secret are deliberately retained. Revoking a certificate requires the
    /// account key that issued it, so deleting a deactivated account would strip the ability to
    /// revoke everything it ever issued — exactly when that ability is most likely to be needed.
    /// </remarks>
    public void Deactivate(DateTimeOffset now)
    {
        IsActive = false;
        ModifiedUtc = now;
    }
}
