using MailServer.Application.Smtp.Dtos;
using MailServer.Application.Abstractions.Smtp;
using System.Data.Common;
using System.Reflection;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Common;
using MailServer.Application.Domains.Dtos;
using MailServer.Application.Monitoring.Dtos;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;

namespace MailServer.Ipc.Tests.Doubles;

/// <summary>
/// Substitutes for the persistence layer only.
/// </summary>
/// <remarks>
/// The end-to-end IPC tests replace the database and the clock and nothing else. Everything
/// the IPC layer exists to do runs for real: framing, version negotiation, registry lookup,
/// identity assignment, the full MediatR pipeline, the real handlers, and error mapping.
/// Substituting more would turn an integration test into a mock-verification exercise.
/// </remarks>
internal sealed class FixedClock : IClock
{
    public DateTimeOffset UtcNow { get; } = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    public long GetTimestamp() => 0;

    public TimeSpan GetElapsedTime(long startingTimestamp) => TimeSpan.Zero;
}

internal sealed class FakeDomainRepository : IDomainRepository
{
    private readonly Dictionary<DomainId, MailDomain> _byId = [];
    private readonly Lock _gate = new();

    public IReadOnlyList<MailDomain> All
    {
        get
        {
            lock (_gate)
            {
                return [.. _byId.Values];
            }
        }
    }

    public Task<MailDomain?> GetByIdAsync(DomainId id, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult(_byId.TryGetValue(id, out MailDomain? d) ? d : null);
        }
    }

    public Task<MailDomain?> GetByNameAsync(DomainName name, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult(_byId.Values.FirstOrDefault(d => d.Name == name));
        }
    }

    public Task<bool> ExistsAsync(DomainName name, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult(_byId.Values.Any(d => d.Name == name));
        }
    }

    public Task<IReadOnlyList<MailDomain>> GetAllAsync(CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult<IReadOnlyList<MailDomain>>([.. _byId.Values]);
        }
    }

    public Task<IReadOnlyList<MailDomain>> GetOperationalAsync(CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult<IReadOnlyList<MailDomain>>(
                [.. _byId.Values.Where(d => d.IsOperational)]);
        }
    }

    public Task AddAsync(MailDomain domain, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _byId[domain.Id] = domain;
        }

        return Task.CompletedTask;
    }

    public Task UpdateAsync(MailDomain domain, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _byId[domain.Id] = domain;
        }

        return Task.CompletedTask;
    }

    public Task RemoveAsync(DomainId id, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _byId.Remove(id);
        }

        return Task.CompletedTask;
    }

    public Task<int> CountMailboxesAsync(DomainId id, CancellationToken cancellationToken) =>
        Task.FromResult(0);
}

/// <summary>Projects the in-memory aggregates into the read model the grid expects.</summary>
internal sealed class FakeDomainQueries(FakeDomainRepository repository) : IDomainQueries
{
    public Task<PagedResult<DomainSummaryDto>> SearchAsync(
        DomainSearchRequest request,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<MailDomain> all = repository.All;

        IEnumerable<MailDomain> filtered = all;

        if (!string.IsNullOrWhiteSpace(request.NameContains))
        {
            filtered = filtered.Where(d =>
                d.Name.Value.Contains(request.NameContains, StringComparison.OrdinalIgnoreCase));
        }

        if (request.Statuses is { Count: > 0 })
        {
            filtered = filtered.Where(d => request.Statuses.Contains(d.Status));
        }

        MailDomain[] ordered = [.. filtered.OrderBy(d => d.Name.Value, StringComparer.Ordinal)];

        DomainSummaryDto[] page =
        [
            .. ordered
                .Skip(request.Skip)
                .Take(request.PageSize)
                .Select(ToSummary)
        ];

        return Task.FromResult(new PagedResult<DomainSummaryDto>(
            page,
            request.Page,
            request.PageSize,
            request.IncludeTotalCount ? ordered.Length : null));
    }

    public Task<DomainDetailDto?> GetDetailAsync(DomainId id, CancellationToken cancellationToken)
    {
        MailDomain? domain = repository.All.FirstOrDefault(d => d.Id == id);

        return Task.FromResult(domain is null ? null : ToDetail(domain));
    }

    private static DomainSummaryDto ToSummary(MailDomain d) => new()
    {
        Id = d.Id.Value,
        Name = d.Name.Value,
        DisplayName = d.Name.UnicodeValue,
        Status = d.Status,
        MailHostname = d.MailHostname?.Value,
        ActiveDkimSelector = d.ActiveDkimSelector?.Value,
        MailboxCount = 0,
        StorageUsedBytes = 0,
        CreatedUtc = d.CreatedUtc,
    };

    private static DomainDetailDto ToDetail(MailDomain d) => new()
    {
        Id = d.Id.Value,
        Name = d.Name.Value,
        DisplayName = d.Name.UnicodeValue,
        Status = d.Status,
        MailHostname = d.MailHostname?.Value,
        ActiveDkimSelector = d.ActiveDkimSelector?.Value,
        CatchAllPolicy = d.CatchAllPolicy,
        CatchAllMailbox = d.CatchAllMailbox?.NormalizedValue,
        DefaultMailboxQuotaBytes = d.DefaultMailboxQuota.Bytes,
        DomainQuotaBytes = d.DomainQuota.Bytes,
        MaxMessageSizeBytes = d.MaxMessageSizeBytes,
        RequireTlsForOutbound = d.RequireTlsForOutbound,
        MailboxCount = 0,
        AliasCount = 0,
        StorageUsedBytes = 0,
        CreatedUtc = d.CreatedUtc,
        ModifiedUtc = d.ModifiedUtc,
    };
}

internal sealed class FakeServerStatusQueries : IServerStatusQueries
{
    public Task<ServerCountersDto> GetCountersAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new ServerCountersDto
        {
            DomainCount = 0,
            ActiveDomainCount = 0,
            MailboxCount = 0,
            QueuedMessageCount = 0,
            DeferredMessageCount = 0,
            StorageUsedBytes = 0,
        });
}

internal sealed class FakeHealthRegistry : IHealthRegistry
{
    private readonly List<HealthReading> _readings = [];

    public void Publish(HealthReading reading) => _readings.Add(reading);

    public void Publish(string component, HealthState state, string message) =>
        _readings.Add(new HealthReading(component, state, message, DateTimeOffset.UtcNow));

    public IReadOnlyList<HealthReading> GetAll() => _readings;

    public HealthReading? Get(string component) =>
        _readings.FirstOrDefault(r => r.Component == component);

    public HealthState GetOverallState() => HealthState.Healthy;
}

internal sealed class FakeMaintenanceMode : IMaintenanceModeAccessor
{
    public MaintenanceMode Current => MaintenanceMode.Normal;

    public bool IsInboundEnabled => true;

    public bool IsOutboundEnabled => true;

    public bool AreAdministrativeWritesEnabled => true;

    public Task SetAsync(MaintenanceMode mode, CancellationToken cancellationToken) =>
        Task.CompletedTask;
}

internal sealed class FakeEnvironmentInfo : IEnvironmentInfo
{
    public string MachineName => "TEST-MACHINE";

    public string ProcessAccount => "TEST-ACCOUNT";

    public string OperatingSystem => "Test OS";

    public string RuntimeVersion => "Test Runtime";

    public string ProductVersion => "0.1.0-test";

    public bool IsWindows => System.OperatingSystem.IsWindows();

    public bool IsWindowsService => false;

    public long GetAvailableFreeSpaceBytes(string path) => long.MaxValue;
}

internal sealed class FakeServerIdentity : IServerIdentityProvider
{
    public string Hostname => "mail.test.example";

    public string? PublicIpAddress => "203.0.113.10";

    public string ProductName => "AetherMail Server";
}

internal sealed class FakeSqlDialect : ISqlDialect
{
    public string Name => "Fake";

    public bool RequiresSerializedWrites => false;

    public bool SupportsTransactionalDdl => true;

    public string QuoteIdentifier(string identifier) => identifier;

    public string PagingClause(int take, int skip) => string.Empty;

    public string UtcNowExpression => "now";

    public bool IsTransient(DbException exception) => false;

    public bool IsUniqueConstraintViolation(DbException exception) => false;

    public string? AcquireMigrationLockSql => null;

    public string? ReleaseMigrationLockSql => null;

    public string MigrationsResourcePrefix => "Fake.";

    public Assembly MigrationsAssembly => typeof(FakeSqlDialect).Assembly;
}

/// <summary>Mirrors the real scoped admin context, including its deny-by-default start.</summary>
internal sealed class ScopedAdminContext : IAdminContext, IAdminContextInitializer
{
    public string Administrator { get; private set; } = "(unauthenticated)";

    public string? SessionIdentifier { get; private set; }

    public bool IsSystem { get; private set; }

    public bool IsAuthenticated { get; private set; }

    public AdminPermission Permissions { get; private set; } = AdminPermission.None;

    public bool MustChangePassword { get; private set; }

    public void Assign(
        string administrator,
        string? sessionIdentifier,
        AdminPermission permissions,
        bool isSystem = false,
        bool mustChangePassword = false)
    {
        Administrator = administrator;
        SessionIdentifier = sessionIdentifier;
        Permissions = permissions;
        IsSystem = isSystem;
        MustChangePassword = mustChangePassword;
        IsAuthenticated = true;
    }

    public bool HasPermission(AdminPermission permission) =>
        IsAuthenticated && (Permissions & permission) == permission;
}

internal sealed class ScopedCorrelationContext : ICorrelationContext
{
    private CorrelationId? _id;

    public CorrelationId CorrelationId => _id ??= CorrelationId.New();

    public void Initialize(CorrelationId correlationId) => _id ??= correlationId;
}

internal sealed class RecordingAuditTrail : IAuditTrail
{
    private readonly List<AuditDescriptor> _deferred = [];

    public bool HasDeferredRecords => _deferred.Count > 0;

    public Task RecordAsync(
        AuditDescriptor descriptor,
        AuditResult result,
        string? detail,
        CancellationToken cancellationToken) => Task.CompletedTask;

    public void QueueDeferred(AuditDescriptor descriptor, AuditResult result, string? detail) =>
        _deferred.Add(descriptor);

    public Task FlushDeferredAsync(CancellationToken cancellationToken)
    {
        _deferred.Clear();
        return Task.CompletedTask;
    }
}

/// <summary>
/// Runs the action without a real transaction.
/// </summary>
/// <remarks>
/// These tests use an in-memory repository, so there is no database to open a transaction
/// against. <c>TransactionBehavior</c> still runs for real and still distinguishes commands
/// from queries; only the commit is a no-op. Real transaction semantics are covered against
/// actual SQLite in <c>MailServer.Persistence.Tests</c>.
/// </remarks>
internal sealed class PassThroughTransactionManager : ITransactionManager
{
    public Task<T> ExecuteAsync<T>(
        Func<DbConnection, DbTransaction, CancellationToken, Task<T>> action,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("Not used by the IPC tests.");

    public Task ExecuteAsync(
        Func<DbConnection, DbTransaction, CancellationToken, Task> action,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("Not used by the IPC tests.");

    public Task<T> ExecuteScopedAsync<T>(
        Func<CancellationToken, Task<T>> action,
        CancellationToken cancellationToken = default) => action(cancellationToken);
}

/// <summary>Buffers security events in memory so tests can assert on them.</summary>
internal sealed class RecordingSecurityEventRecorder : ISecurityEventRecorder
{
    private readonly List<(SecurityEventType Type, string? Subject, string Description)> _pending = [];

    public List<(SecurityEventType Type, string? Subject, string Description)> Flushed { get; } = [];

    public bool HasPendingEvents => _pending.Count > 0;

    public Task RecordAsync(
        SecurityEventType eventType,
        string? subject,
        string? origin,
        string description,
        CancellationToken cancellationToken)
    {
        _pending.Add((eventType, subject, description));
        return Task.CompletedTask;
    }

    public Task FlushAsync(CancellationToken cancellationToken)
    {
        Flushed.AddRange(_pending);
        _pending.Clear();
        return Task.CompletedTask;
    }
}

/// <summary>Security settings with short timeouts, so expiry is testable.</summary>
internal sealed class FakeSecuritySettings : ISecuritySettings
{
    public TimeSpan SessionIdleTimeout { get; set; } = TimeSpan.FromMinutes(10);

    public TimeSpan SessionAbsoluteTimeout { get; set; } = TimeSpan.FromHours(12);

    public LockoutPolicy LockoutPolicy { get; } = new();

    public int MinimumPasswordLength => 12;
}

/// <summary>
/// An admin account repository holding nothing, so the server under test looks like one that
/// has not been through first-run setup.
/// </summary>
/// <remarks>
/// That is the state in which the four anonymous commands matter most, and it lets the
/// authorization tests prove those commands are genuinely reachable without a session rather
/// than merely failing differently.
/// </remarks>
internal sealed class EmptyAdminAccountRepository : IAdminAccountRepository
{
    public Task<AdminAccount?> GetBuiltInAsync(CancellationToken cancellationToken) =>
        Task.FromResult<AdminAccount?>(null);

    public Task<AdminAccount?> GetByIdAsync(AdminAccountId id, CancellationToken cancellationToken) =>
        Task.FromResult<AdminAccount?>(null);

    public Task<AdminAccount?> GetByNameAsync(string name, CancellationToken cancellationToken) =>
        Task.FromResult<AdminAccount?>(null);

    public Task<bool> AnyAsync(CancellationToken cancellationToken) => Task.FromResult(false);

    public Task AddAsync(AdminAccount account, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public Task UpdateAsync(AdminAccount account, CancellationToken cancellationToken) =>
        Task.CompletedTask;
}

/// <summary>
/// A TLS reload coordinator that records the intent instead of rebuilding a snapshot.
/// </summary>
/// <remarks>
/// The IPC tests do not configure certificates, but the reload behavior sits in the pipeline
/// for every request, so the container must be able to resolve this. Recording rather than
/// no-opping means a test can still assert that a command asked for a reload.
/// </remarks>
internal sealed class RecordingTlsReloadCoordinator : ITlsReloadCoordinator
{
    public int FlushCount { get; private set; }

    public bool ReloadRequested { get; private set; }

    public void RequestReload() => ReloadRequested = true;

    public Task FlushAsync(CancellationToken cancellationToken)
    {
        ReloadRequested = false;
        FlushCount++;
        return Task.CompletedTask;
    }
}

/// <summary>One received message, so the read side has something to return.</summary>
internal sealed class FakeSmtpQueries : ISmtpQueries
{
    public Task<PagedResult<ReceivedMessageDto>> SearchReceivedAsync(
        ReceivedMessageSearchRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new PagedResult<ReceivedMessageDto>(
            [
                new ReceivedMessageDto
                {
                    Id = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e"),
                    SizeBytes = 2048,
                    ContentSha256 = new string('a', 64),
                    ReversePath = "sender@example.net",
                    RemoteAddress = "198.51.100.20",
                    GreetedName = "relay.example.net",
                    ListenerRole = SmtpListenerRole.InboundMta,
                    TlsActive = true,
                    ReceivedUtc = new DateTimeOffset(2026, 3, 1, 9, 0, 0, TimeSpan.Zero),
                    Recipients = [new ReceivedRecipientDto("user@example.com", RelayDecision.AcceptLocal)],
                    DeliveryCount = 1,
                },
            ],
            request.Page,
            request.PageSize,
            1));

    public Task<(long LastDay, long LastHour, long StoredBytes)> GetThroughputAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        Task.FromResult((LastDay: 12L, LastHour: 3L, StoredBytes: 2048L));
}

/// <summary>The default listener configuration, as shipped.</summary>
internal sealed class FakeSmtpConfigurationView : ISmtpConfigurationView
{
    public bool IsAuthenticationAvailable => false;

    public IReadOnlyList<string> AuthorizedRelayAddresses => [];

    public IReadOnlyList<SmtpListenerStatusDto> DescribeListeners() =>
    [
        Describe(SmtpListenerRole.InboundMta, 25, enabled: true),
        Describe(SmtpListenerRole.Submission, 587, enabled: false),
        Describe(SmtpListenerRole.ImplicitTlsSubmission, 465, enabled: false),
    ];

    private static SmtpListenerStatusDto Describe(SmtpListenerRole role, int port, bool enabled) => new()
    {
        Role = role,
        Port = port,
        Enabled = enabled,
        BindAddresses = [],

        // Authentication is unavailable, so no listener offers it - which is what the real
        // configuration view computes from SmtpCapabilities rather than restating.
        OffersAuthentication = false,
        CanRelayForAuthenticatedSenders = false,
    };
}
