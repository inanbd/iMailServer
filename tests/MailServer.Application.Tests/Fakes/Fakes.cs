using System.Data.Common;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Tests.Fakes;

/// <summary>A clock that does not move unless a test moves it.</summary>
/// <remarks>
/// Every time-dependent rule in this product - retry backoff, certificate expiry, lockout
/// windows, queue lifetime - is tested against this rather than the wall clock. Tests that
/// sleep to advance time are slow and flaky, and tests that read the real clock cannot assert
/// on an exact value.
/// </remarks>
public sealed class FakeClock(DateTimeOffset? start = null) : IClock
{
    private long _timestamp;

    public DateTimeOffset UtcNow { get; private set; } =
        start ?? new DateTimeOffset(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    public void Advance(TimeSpan by)
    {
        UtcNow = UtcNow.Add(by);
        _timestamp += (long)(by.TotalSeconds * TimeSpan.TicksPerSecond);
    }

    public long GetTimestamp() => _timestamp;

    public TimeSpan GetElapsedTime(long startingTimestamp) =>
        TimeSpan.FromTicks(_timestamp - startingTimestamp);
}

/// <summary>An in-memory domain repository.</summary>
public sealed class FakeDomainRepository : IDomainRepository
{
    private readonly Dictionary<DomainId, MailDomain> _byId = [];

    public int MailboxCountToReport { get; set; }

    public IReadOnlyCollection<MailDomain> All => _byId.Values;

    public void Seed(MailDomain domain) => _byId[domain.Id] = domain;

    public Task<MailDomain?> GetByIdAsync(DomainId id, CancellationToken cancellationToken) =>
        Task.FromResult(_byId.TryGetValue(id, out MailDomain? domain) ? domain : null);

    public Task<MailDomain?> GetByNameAsync(DomainName name, CancellationToken cancellationToken) =>
        Task.FromResult(_byId.Values.FirstOrDefault(d => d.Name == name));

    public Task<bool> ExistsAsync(DomainName name, CancellationToken cancellationToken) =>
        Task.FromResult(_byId.Values.Any(d => d.Name == name));

    public Task<IReadOnlyList<MailDomain>> GetAllAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<MailDomain>>([.. _byId.Values]);

    public Task<IReadOnlyList<MailDomain>> GetOperationalAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<MailDomain>>([.. _byId.Values.Where(d => d.IsOperational)]);

    public Task AddAsync(MailDomain domain, CancellationToken cancellationToken)
    {
        _byId[domain.Id] = domain;
        return Task.CompletedTask;
    }

    public Task UpdateAsync(MailDomain domain, CancellationToken cancellationToken)
    {
        _byId[domain.Id] = domain;
        return Task.CompletedTask;
    }

    public Task RemoveAsync(DomainId id, CancellationToken cancellationToken)
    {
        _byId.Remove(id);
        return Task.CompletedTask;
    }

    public Task<int> CountMailboxesAsync(DomainId id, CancellationToken cancellationToken) =>
        Task.FromResult(MailboxCountToReport);
}

/// <summary>Records what the pipeline asked to be audited, without touching a database.</summary>
public sealed class FakeAuditTrail : IAuditTrail
{
    public List<(AuditDescriptor Descriptor, AuditResult Result, string? Detail)> Recorded { get; } = [];

    public List<(AuditDescriptor Descriptor, AuditResult Result, string? Detail)> Deferred { get; } = [];

    public int FlushCount { get; private set; }

    public bool HasDeferredRecords => Deferred.Count > 0;

    public Task RecordAsync(
        AuditDescriptor descriptor,
        AuditResult result,
        string? detail,
        CancellationToken cancellationToken)
    {
        Recorded.Add((descriptor, result, detail));
        return Task.CompletedTask;
    }

    public void QueueDeferred(AuditDescriptor descriptor, AuditResult result, string? detail) =>
        Deferred.Add((descriptor, result, detail));

    public Task FlushDeferredAsync(CancellationToken cancellationToken)
    {
        FlushCount++;
        return Task.CompletedTask;
    }
}

/// <summary>An admin identity whose permissions a test can dial up or down.</summary>
public sealed class FakeAdminContext(
    AdminPermission permissions = AdminPermission.FullControl,
    bool isAuthenticated = true,
    bool mustChangePassword = false) : IAdminContext
{
    public string Administrator => "test-administrator";

    public string? SessionIdentifier => "test-session";

    public bool IsSystem => false;

    public bool IsAuthenticated { get; } = isAuthenticated;

    public AdminPermission Permissions { get; } = permissions;

    /// <summary>
    /// Set by the recovery-key reset path. While true, the authorization behavior must refuse
    /// everything except changing the password and signing out.
    /// </summary>
    public bool MustChangePassword { get; } = mustChangePassword;

    public bool HasPermission(AdminPermission permission) =>
        IsAuthenticated && (Permissions & permission) == permission;
}

/// <summary>A maintenance mode a test can set directly.</summary>
public sealed class FakeMaintenanceMode(MaintenanceMode mode = MaintenanceMode.Normal)
    : IMaintenanceModeAccessor
{
    public MaintenanceMode Current { get; private set; } = mode;

    public bool IsInboundEnabled => Current is MaintenanceMode.Normal or MaintenanceMode.OutboundPaused;

    public bool IsOutboundEnabled => Current is MaintenanceMode.Normal
                                              or MaintenanceMode.InboundPaused
                                              or MaintenanceMode.QueueOnly;

    public bool AreAdministrativeWritesEnabled =>
        Current is not (MaintenanceMode.ReadOnly or MaintenanceMode.FullMaintenance);

    public Task SetAsync(MaintenanceMode newMode, CancellationToken cancellationToken)
    {
        Current = newMode;
        return Task.CompletedTask;
    }
}

/// <summary>A correlation context with the same semantics as the real one.</summary>
public sealed class FakeCorrelationContext : ICorrelationContext
{
    private CorrelationId? _id;

    public CorrelationId CorrelationId => _id ??= CorrelationId.New();

    public void Initialize(CorrelationId correlationId) => _id ??= correlationId;
}

/// <summary>
/// A transaction manager that records whether a transaction was opened.
/// </summary>
/// <remarks>
/// Used to assert the property that matters most about <c>TransactionBehavior</c>: commands
/// get a transaction and queries do not. Opening one for a read costs a writer slot, which
/// under SQLite is a direct throughput loss.
/// </remarks>
public sealed class FakeTransactionManager : ITransactionManager
{
    public int ScopedTransactionCount { get; private set; }

    public Task<T> ExecuteAsync<T>(
        Func<DbConnection, DbTransaction, CancellationToken, Task<T>> action,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("Not used by the behavior tests.");

    public Task ExecuteAsync(
        Func<DbConnection, DbTransaction, CancellationToken, Task> action,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("Not used by the behavior tests.");

    public Task<T> ExecuteScopedAsync<T>(
        Func<CancellationToken, Task<T>> action,
        CancellationToken cancellationToken = default)
    {
        ScopedTransactionCount++;
        return action(cancellationToken);
    }
}
