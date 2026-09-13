using System.Data.Common;
using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Persistence.Repositories;

/// <summary>
/// Dapper-backed <see cref="IDomainRepository"/>, written once for both providers.
/// </summary>
/// <remarks>
/// <para>
/// The SQL here is portable between SQLite and SQL Server; anything that is not portable
/// goes through <see cref="ISqlDialect"/>. Maintaining two hand-written copies of the same
/// statements is where provider drift breeds, and drift in a mail store means bugs that
/// appear on only one provider and are therefore found in production.
/// </para>
/// <para>
/// <b>Every statement is fully parameterised.</b> No user-supplied value is ever
/// concatenated into SQL. The one thing that cannot be parameterised - the ORDER BY column -
/// is selected from a closed enum through a switch, never from caller-supplied text.
/// </para>
/// </remarks>
internal sealed class DomainRepository(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), IDomainRepository
{
    private const string SelectColumns = """
        SELECT  Id, Name, UnicodeName, Status, MailHostname, ActiveDkimSelector,
                CatchAllPolicy, CatchAllMailbox, DefaultMailboxQuotaBytes, DomainQuotaBytes,
                MaxMessageSizeBytes, RequireTlsForOutbound, CreatedUtc, ModifiedUtc
        FROM    Domains
        """;

    public Task<MailDomain?> GetByIdAsync(DomainId id, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            DomainRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<DomainRow>(
                    Command(session, $"{SelectColumns} WHERE Id = @Id", new { Id = id.Value }, ct))
                .ConfigureAwait(false);

            return row is null ? null : DomainRowMapper.ToAggregate(row);
        }, cancellationToken);

    public Task<MailDomain?> GetByNameAsync(DomainName name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(name);

        return ExecuteAsync(async (session, ct) =>
        {
            DomainRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<DomainRow>(
                    Command(session, $"{SelectColumns} WHERE Name = @Name", new { Name = name.Value }, ct))
                .ConfigureAwait(false);

            return row is null ? null : DomainRowMapper.ToAggregate(row);
        }, cancellationToken);
    }

    public Task<bool> ExistsAsync(DomainName name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(name);

        return ExecuteAsync(async (session, ct) =>
        {
            // COUNT rather than SELECT *: existence checks run on the SMTP path and there is
            // no reason to transfer a row to answer a yes/no question.
            int count = await session.Connection
                .ExecuteScalarAsync<int>(Command(
                    session,
                    "SELECT COUNT(1) FROM Domains WHERE Name = @Name",
                    new { Name = name.Value },
                    ct))
                .ConfigureAwait(false);

            return count > 0;
        }, cancellationToken);
    }

    public Task<IReadOnlyList<MailDomain>> GetAllAsync(CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            IEnumerable<DomainRow> rows = await session.Connection
                .QueryAsync<DomainRow>(Command(session, $"{SelectColumns} ORDER BY Name", null, ct))
                .ConfigureAwait(false);

            return (IReadOnlyList<MailDomain>)[.. rows.Select(DomainRowMapper.ToAggregate)];
        }, cancellationToken);

    public Task<IReadOnlyList<MailDomain>> GetOperationalAsync(CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            IEnumerable<DomainRow> rows = await session.Connection
                .QueryAsync<DomainRow>(Command(
                    session,
                    $"{SelectColumns} WHERE Status = @Status ORDER BY Name",
                    new { Status = (int)DomainStatus.Active },
                    ct))
                .ConfigureAwait(false);

            return (IReadOnlyList<MailDomain>)[.. rows.Select(DomainRowMapper.ToAggregate)];
        }, cancellationToken);

    public Task AddAsync(MailDomain domain, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domain);

        const string Sql = """
            INSERT INTO Domains
                (Id, Name, UnicodeName, Status, MailHostname, ActiveDkimSelector,
                 CatchAllPolicy, CatchAllMailbox, DefaultMailboxQuotaBytes, DomainQuotaBytes,
                 MaxMessageSizeBytes, RequireTlsForOutbound, CreatedUtc, ModifiedUtc)
            VALUES
                (@Id, @Name, @UnicodeName, @Status, @MailHostname, @ActiveDkimSelector,
                 @CatchAllPolicy, @CatchAllMailbox, @DefaultMailboxQuotaBytes, @DomainQuotaBytes,
                 @MaxMessageSizeBytes, @RequireTlsForOutbound, @CreatedUtc, @ModifiedUtc)
            """;

        return ExecuteAsync(async (session, ct) =>
        {
            try
            {
                await session.Connection
                    .ExecuteAsync(Command(session, Sql, DomainRowMapper.ToParameters(domain), ct))
                    .ConfigureAwait(false);
            }
            catch (DbException ex) when (Dialect.IsUniqueConstraintViolation(ex))
            {
                // The handler's pre-check gives a good message in the common case; this is
                // what actually guarantees correctness when two administrators create the
                // same domain at the same instant and both pass that pre-check.
                throw new DuplicateEntityException(nameof(MailDomain), domain.Name.Value);
            }

            return true;
        }, cancellationToken);
    }

    public Task UpdateAsync(MailDomain domain, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domain);

        // Name and UnicodeName are deliberately absent from the SET list: the domain name is
        // immutable, and a repository that could change it would silently defeat that rule.
        const string Sql = """
            UPDATE Domains
            SET    Status                   = @Status,
                   MailHostname             = @MailHostname,
                   ActiveDkimSelector       = @ActiveDkimSelector,
                   CatchAllPolicy           = @CatchAllPolicy,
                   CatchAllMailbox          = @CatchAllMailbox,
                   DefaultMailboxQuotaBytes = @DefaultMailboxQuotaBytes,
                   DomainQuotaBytes         = @DomainQuotaBytes,
                   MaxMessageSizeBytes      = @MaxMessageSizeBytes,
                   RequireTlsForOutbound    = @RequireTlsForOutbound,
                   ModifiedUtc              = @ModifiedUtc
            WHERE  Id = @Id
            """;

        return ExecuteAsync(async (session, ct) =>
        {
            int affected = await session.Connection
                .ExecuteAsync(Command(session, Sql, DomainRowMapper.ToParameters(domain), ct))
                .ConfigureAwait(false);

            if (affected == 0)
            {
                // Silently updating nothing is how "I saved it and it didn't save" bugs
                // happen. The row was deleted underneath us; say so.
                throw new EntityNotFoundException(nameof(MailDomain), domain.Id.ToString());
            }

            return affected;
        }, cancellationToken);
    }

    public Task RemoveAsync(DomainId id, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            int affected = await session.Connection
                .ExecuteAsync(Command(
                    session,
                    "DELETE FROM Domains WHERE Id = @Id",
                    new { Id = id.Value },
                    ct))
                .ConfigureAwait(false);

            if (affected == 0)
            {
                throw new EntityNotFoundException(nameof(MailDomain), id.ToString());
            }

            return affected;
        }, cancellationToken);

    public Task<int> CountMailboxesAsync(DomainId id, CancellationToken cancellationToken) =>
        ExecuteAsync((session, ct) => session.Connection
            .ExecuteScalarAsync<int>(Command(
                session,
                "SELECT COUNT(1) FROM Mailboxes WHERE DomainId = @DomainId",
                new { DomainId = id.Value },
                ct)), cancellationToken);
}
