using MailServer.Domain.Entities;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Repositories;

/// <summary>Loads and persists mailboxes, their credentials and their folders.</summary>
/// <remarks>
/// Credentials and folders share this repository rather than having their own, because they
/// have no independent lifetime: both are created with the mailbox, both are meaningless
/// without it, and separate repositories would let a handler create one without the other.
/// </remarks>
public interface IMailboxRepository
{
    Task<Mailbox?> GetAsync(MailboxId id, CancellationToken cancellationToken);

    /// <summary>
    /// Resolves a recipient address.
    /// </summary>
    /// <remarks>
    /// The hottest read in the product once SMTP exists: one per RCPT TO. It matches on the
    /// normalised address, which is what <c>UX_Mailboxes_Address</c> indexes.
    /// </remarks>
    Task<Mailbox?> GetByAddressAsync(EmailAddress address, CancellationToken cancellationToken);

    Task<bool> AddressExistsAsync(EmailAddress address, CancellationToken cancellationToken);

    Task<IReadOnlyList<Mailbox>> GetByDomainAsync(
        DomainId domainId,
        CancellationToken cancellationToken);

    /// <summary>How many mailboxes a domain has, without loading them.</summary>
    Task<int> CountByDomainAsync(DomainId domainId, CancellationToken cancellationToken);

    Task AddAsync(Mailbox mailbox, CancellationToken cancellationToken);

    Task UpdateAsync(Mailbox mailbox, CancellationToken cancellationToken);

    Task RemoveAsync(MailboxId id, CancellationToken cancellationToken);

    // ---- Credentials --------------------------------------------------------------------

    Task<MailboxCredential?> GetCredentialAsync(
        MailboxId mailboxId,
        CancellationToken cancellationToken);

    Task AddCredentialAsync(MailboxCredential credential, CancellationToken cancellationToken);

    Task UpdateCredentialAsync(MailboxCredential credential, CancellationToken cancellationToken);

    // ---- Folders ------------------------------------------------------------------------

    Task<IReadOnlyList<MailboxFolder>> GetFoldersAsync(
        MailboxId mailboxId,
        CancellationToken cancellationToken);

    Task AddFolderAsync(MailboxFolder folder, CancellationToken cancellationToken);

    Task UpdateFolderAsync(MailboxFolder folder, CancellationToken cancellationToken);

    Task RemoveFolderAsync(MailboxFolderId id, CancellationToken cancellationToken);
}

/// <summary>Loads and persists aliases.</summary>
public interface IAliasRepository
{
    Task<Alias?> GetAsync(AliasId id, CancellationToken cancellationToken);

    Task<Alias?> GetByAddressAsync(EmailAddress address, CancellationToken cancellationToken);

    Task<bool> AddressExistsAsync(EmailAddress address, CancellationToken cancellationToken);

    Task<IReadOnlyList<Alias>> GetByDomainAsync(
        DomainId domainId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Every enabled alias, for building an expansion map.
    /// </summary>
    /// <remarks>
    /// Loaded wholesale rather than walked one lookup at a time, because expansion follows a
    /// graph and a per-hop query would turn one RCPT TO into a query per hop. The alias count
    /// on a mail server is small and bounded — this is a few hundred rows, not a table scan of
    /// messages.
    /// </remarks>
    Task<IReadOnlyList<Alias>> GetAllEnabledAsync(CancellationToken cancellationToken);

    Task AddAsync(Alias alias, CancellationToken cancellationToken);

    Task UpdateAsync(Alias alias, CancellationToken cancellationToken);

    Task RemoveAsync(AliasId id, CancellationToken cancellationToken);
}
