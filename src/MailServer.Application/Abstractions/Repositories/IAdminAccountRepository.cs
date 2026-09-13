using MailServer.Domain.Entities;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Repositories;

/// <summary>
/// Loads and persists the <see cref="AdminAccount"/> aggregate.
/// </summary>
/// <remarks>
/// Milestone 2 has a single built-in administrator, so <see cref="GetBuiltInAsync"/> is the
/// method almost everything uses. The by-name and by-id lookups exist because a delegated
/// administration model is a permission set rather than a rewrite, and callers written against
/// them today will not need changing when that arrives.
/// </remarks>
public interface IAdminAccountRepository
{
    /// <summary>The built-in administrator, or null before first-run setup has completed.</summary>
    Task<AdminAccount?> GetBuiltInAsync(CancellationToken cancellationToken);

    Task<AdminAccount?> GetByIdAsync(AdminAccountId id, CancellationToken cancellationToken);

    Task<AdminAccount?> GetByNameAsync(string name, CancellationToken cancellationToken);

    /// <summary>
    /// True when any administrator account exists.
    /// </summary>
    /// <remarks>
    /// Drives the first-run wizard. Deliberately cheap and callable without a session, since it
    /// is the one thing an unauthenticated client is entitled to ask: whether setup is needed.
    /// </remarks>
    Task<bool> AnyAsync(CancellationToken cancellationToken);

    Task AddAsync(AdminAccount account, CancellationToken cancellationToken);

    Task UpdateAsync(AdminAccount account, CancellationToken cancellationToken);
}
