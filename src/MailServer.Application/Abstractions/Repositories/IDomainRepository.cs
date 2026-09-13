using MailServer.Domain.Entities;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Repositories;

/// <summary>
/// Loads and persists the <see cref="MailDomain"/> aggregate.
/// </summary>
/// <remarks>
/// <para>
/// Repositories return domain objects and enforce nothing themselves - the aggregate
/// enforces its own invariants. They exist so that a command handler can say "give me this
/// domain, tell it to do something, save it" without knowing that SQL exists.
/// </para>
/// <para>
/// Read models for grids and dashboards do <b>not</b> come from here; see
/// <see cref="Queries.IDomainQueries"/>. Forcing a paged, filtered, sorted 10 000-row grid
/// through aggregate rehydration would be slow and would build objects nobody needs.
/// </para>
/// </remarks>
public interface IDomainRepository
{
    Task<MailDomain?> GetByIdAsync(DomainId id, CancellationToken cancellationToken);

    Task<MailDomain?> GetByNameAsync(DomainName name, CancellationToken cancellationToken);

    Task<bool> ExistsAsync(DomainName name, CancellationToken cancellationToken);

    Task<IReadOnlyList<MailDomain>> GetAllAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Every domain currently accepting mail. Cached by the SMTP path, because this is
    /// consulted on every single RCPT TO.
    /// </summary>
    Task<IReadOnlyList<MailDomain>> GetOperationalAsync(CancellationToken cancellationToken);

    Task AddAsync(MailDomain domain, CancellationToken cancellationToken);

    Task UpdateAsync(MailDomain domain, CancellationToken cancellationToken);

    Task RemoveAsync(DomainId id, CancellationToken cancellationToken);

    /// <summary>
    /// Number of mailboxes in the domain. Used to refuse deletion of a domain that still
    /// holds mail, which would otherwise orphan every message in the store.
    /// </summary>
    Task<int> CountMailboxesAsync(DomainId id, CancellationToken cancellationToken);
}
