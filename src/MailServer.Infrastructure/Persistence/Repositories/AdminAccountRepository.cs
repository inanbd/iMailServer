using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Persistence.Repositories;

/// <summary>Flat shape of an <c>AdminAccounts</c> row.</summary>
/// <remarks>
/// A separate type from the aggregate, for the same reason as <c>DomainRow</c>: letting Dapper
/// populate <see cref="AdminAccount"/> directly would require public setters on it, and a
/// public setter on <c>LockedOutUntilUtc</c> would let any caller clear a lockout.
/// </remarks>
internal sealed class AdminAccountRow
{
    public Guid Id { get; set; }

    public string Name { get; set; } = string.Empty;

    public string PasswordHash { get; set; } = string.Empty;

    public string? RecoveryKeyHash { get; set; }

    public int Permissions { get; set; }

    public int ConsecutiveFailures { get; set; }

    public DateTimeOffset? LastFailureUtc { get; set; }

    public DateTimeOffset? LockedOutUntilUtc { get; set; }

    public DateTimeOffset? LastSignInUtc { get; set; }

    public bool MustChangePassword { get; set; }

    public DateTimeOffset CreatedUtc { get; set; }

    public DateTimeOffset? PasswordChangedUtc { get; set; }
}

/// <summary>Persists the <see cref="AdminAccount"/> aggregate.</summary>
internal sealed class AdminAccountRepository(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), IAdminAccountRepository
{
    private const string SelectColumns = """
        SELECT  Id, Name, PasswordHash, RecoveryKeyHash, Permissions, ConsecutiveFailures,
                LastFailureUtc, LockedOutUntilUtc, LastSignInUtc, MustChangePassword,
                CreatedUtc, PasswordChangedUtc
        FROM    AdminAccounts
        """;

    public Task<AdminAccount?> GetBuiltInAsync(CancellationToken cancellationToken) =>
        GetByNameAsync(AdminAccount.BuiltInAdministratorName, cancellationToken);

    public Task<AdminAccount?> GetByIdAsync(AdminAccountId id, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            AdminAccountRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<AdminAccountRow>(
                    Command(session, $"{SelectColumns} WHERE Id = @Id", new { Id = id.Value }, ct))
                .ConfigureAwait(false);

            return row is null ? null : ToAggregate(row);
        }, cancellationToken);

    public Task<AdminAccount?> GetByNameAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        return ExecuteAsync(async (session, ct) =>
        {
            AdminAccountRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<AdminAccountRow>(
                    Command(session, $"{SelectColumns} WHERE Name = @Name", new { Name = name }, ct))
                .ConfigureAwait(false);

            return row is null ? null : ToAggregate(row);
        }, cancellationToken);
    }

    public Task<bool> AnyAsync(CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            int count = await session.Connection
                .ExecuteScalarAsync<int>(Command(
                    session,
                    "SELECT COUNT(1) FROM AdminAccounts",
                    null,
                    ct))
                .ConfigureAwait(false);

            return count > 0;
        }, cancellationToken);

    public Task AddAsync(AdminAccount account, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(account);

        const string Sql = """
            INSERT INTO AdminAccounts
                (Id, Name, PasswordHash, RecoveryKeyHash, Permissions, ConsecutiveFailures,
                 LastFailureUtc, LockedOutUntilUtc, LastSignInUtc, MustChangePassword,
                 CreatedUtc, PasswordChangedUtc)
            VALUES
                (@Id, @Name, @PasswordHash, @RecoveryKeyHash, @Permissions, @ConsecutiveFailures,
                 @LastFailureUtc, @LockedOutUntilUtc, @LastSignInUtc, @MustChangePassword,
                 @CreatedUtc, @PasswordChangedUtc)
            """;

        return ExecuteAsync(async (session, ct) =>
        {
            try
            {
                await session.Connection
                    .ExecuteAsync(Command(session, Sql, ToParameters(account), ct))
                    .ConfigureAwait(false);
            }
            catch (System.Data.Common.DbException ex) when (Dialect.IsUniqueConstraintViolation(ex))
            {
                // Two clients racing to complete first-run setup. The unique index on Name is
                // what actually decides the winner; the handler's AnyAsync pre-check only
                // produces a better message in the common case.
                throw new DuplicateEntityException(nameof(AdminAccount), account.Name);
            }

            return true;
        }, cancellationToken);
    }

    public Task UpdateAsync(AdminAccount account, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(account);

        // Name and CreatedUtc are absent from the SET list: the account's identity does not
        // change, and a repository able to rewrite it would be a way to rename the audit
        // trail's subject after the fact.
        const string Sql = """
            UPDATE AdminAccounts
            SET    PasswordHash        = @PasswordHash,
                   RecoveryKeyHash     = @RecoveryKeyHash,
                   Permissions         = @Permissions,
                   ConsecutiveFailures = @ConsecutiveFailures,
                   LastFailureUtc      = @LastFailureUtc,
                   LockedOutUntilUtc   = @LockedOutUntilUtc,
                   LastSignInUtc       = @LastSignInUtc,
                   MustChangePassword  = @MustChangePassword,
                   PasswordChangedUtc  = @PasswordChangedUtc
            WHERE  Id = @Id
            """;

        return ExecuteAsync(async (session, ct) =>
        {
            int affected = await session.Connection
                .ExecuteAsync(Command(session, Sql, ToParameters(account), ct))
                .ConfigureAwait(false);

            if (affected == 0)
            {
                throw new EntityNotFoundException(nameof(AdminAccount), account.Id.ToString());
            }

            return affected;
        }, cancellationToken);
    }

    private static AdminAccount ToAggregate(AdminAccountRow row) =>
        new(new AdminAccountId(row.Id),
            row.Name,
            PasswordHash.Parse(row.PasswordHash),
            row.RecoveryKeyHash is null ? null : PasswordHash.Parse(row.RecoveryKeyHash),
            (AdminPermission)row.Permissions,
            row.ConsecutiveFailures,
            row.LastFailureUtc,
            row.LockedOutUntilUtc,
            row.LastSignInUtc,
            row.MustChangePassword,
            row.CreatedUtc,
            row.PasswordChangedUtc);

    private static object ToParameters(AdminAccount account) => new
    {
        Id = account.Id.Value,
        account.Name,
        PasswordHash = account.PasswordHash.Encoded,
        RecoveryKeyHash = account.RecoveryKeyHash?.Encoded,
        Permissions = (int)account.Permissions,
        account.ConsecutiveFailures,
        account.LastFailureUtc,
        account.LockedOutUntilUtc,
        account.LastSignInUtc,
        account.MustChangePassword,
        account.CreatedUtc,
        account.PasswordChangedUtc,
    };
}

/// <summary>Append-only security event storage.</summary>
internal sealed class SecurityEventRepository(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), ISecurityEventRepository
{
    public Task AppendAsync(SecurityEvent securityEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);

        const string Sql = """
            INSERT INTO SecurityEvents
                (Id, TimestampUtc, EventType, Subject, Origin, Description,
                 MachineName, CorrelationId, IsAlarming)
            VALUES
                (@Id, @TimestampUtc, @EventType, @Subject, @Origin, @Description,
                 @MachineName, @CorrelationId, @IsAlarming)
            """;

        return ExecuteAsync((session, ct) => session.Connection.ExecuteAsync(Command(
            session,
            Sql,
            new
            {
                Id = securityEvent.Id.Value,
                securityEvent.TimestampUtc,
                EventType = (int)securityEvent.EventType,
                securityEvent.Subject,
                securityEvent.Origin,
                securityEvent.Description,
                securityEvent.MachineName,
                CorrelationId = securityEvent.CorrelationId.Value,
                securityEvent.IsAlarming,
            },
            ct)), cancellationToken);
    }
}
