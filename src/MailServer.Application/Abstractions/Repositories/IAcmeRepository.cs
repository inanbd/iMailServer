using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Repositories;

/// <summary>Counts of prior attempts, for the rate limiter.</summary>
/// <param name="CertificatesForRegisteredDomain">Issued for the registered domain in the window.</param>
/// <param name="DuplicateCertificates">Issued for this exact identifier set in the window.</param>
/// <param name="RecentFailedValidations">Validations that failed at the CA in the failure window.</param>
/// <param name="OldestRelevantAttemptUtc">Oldest attempt still inside a window, so the UI can say when it clears.</param>
public sealed record AcmeAttemptCounts(
    int CertificatesForRegisteredDomain,
    int DuplicateCertificates,
    int RecentFailedValidations,
    DateTimeOffset? OldestRelevantAttemptUtc);

/// <summary>Persists ACME accounts and the issuance history the rate limiter depends on.</summary>
public interface IAcmeRepository
{
    Task<AcmeAccount?> GetAccountAsync(AcmeAccountId id, CancellationToken cancellationToken);

    /// <summary>The active account for a directory, or null when none is registered.</summary>
    Task<AcmeAccount?> GetActiveAccountAsync(
        AcmeDirectory directory,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<AcmeAccount>> GetAccountsAsync(CancellationToken cancellationToken);

    Task AddAccountAsync(AcmeAccount account, CancellationToken cancellationToken);

    Task UpdateAccountAsync(AcmeAccount account, CancellationToken cancellationToken);

    Task<AcmeOrder?> GetOrderAsync(AcmeOrderId id, CancellationToken cancellationToken);

    Task<IReadOnlyList<AcmeOrder>> GetRecentOrdersAsync(
        int limit,
        CancellationToken cancellationToken);

    /// <summary>
    /// Adds an order.
    /// </summary>
    /// <param name="registeredDomain">
    /// The registered domain for rate-limit grouping, computed by the caller — the domain layer
    /// has no Public Suffix List and must not guess at one.
    /// </param>
    Task AddOrderAsync(
        AcmeOrder order,
        string registeredDomain,
        CancellationToken cancellationToken);

    Task UpdateOrderAsync(AcmeOrder order, CancellationToken cancellationToken);

    /// <summary>
    /// Counts prior attempts inside the rate-limit windows.
    /// </summary>
    /// <remarks>
    /// One query rather than three, because it runs before every order and the three counts are
    /// evaluated together. Only orders that actually reached the CA are counted: an order
    /// refused locally consumed no quota, and counting it would make the server progressively
    /// more reluctant to do something that cost nothing.
    /// </remarks>
    Task<AcmeAttemptCounts> CountRecentAttemptsAsync(
        string registeredDomain,
        string identifierSetKey,
        DateTimeOffset weeklyWindowStart,
        DateTimeOffset failureWindowStart,
        CancellationToken cancellationToken);
}
