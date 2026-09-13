using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Entities;

namespace MailServer.Infrastructure.Persistence.Repositories;

/// <summary>
/// Append-only audit storage.
/// </summary>
/// <remarks>
/// There is no UPDATE and no DELETE in this class, and none anywhere else against this
/// table. Retention trimming, when it arrives, will be a separate and itself-audited
/// maintenance operation. An audit trail that ordinary code can edit is not an audit trail.
/// </remarks>
internal sealed class AuditRepository(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), IAuditRepository
{
    private const string InsertSql = """
        INSERT INTO AuditRecords
            (Id, TimestampUtc, Administrator, Action, TargetType, TargetIdentifier,
             Result, Detail, MachineName, SessionIdentifier, CorrelationId)
        VALUES
            (@Id, @TimestampUtc, @Administrator, @Action, @TargetType, @TargetIdentifier,
             @Result, @Detail, @MachineName, @SessionIdentifier, @CorrelationId)
        """;

    public Task AppendAsync(AuditRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);

        return ExecuteAsync((session, ct) => session.Connection.ExecuteAsync(Command(
            session,
            InsertSql,
            new
            {
                Id = record.Id.Value,
                record.TimestampUtc,
                record.Administrator,
                record.Action,
                record.TargetType,
                record.TargetIdentifier,
                Result = (int)record.Result,
                record.Detail,
                record.MachineName,
                record.SessionIdentifier,
                CorrelationId = record.CorrelationId.Value,
            },
            ct)), cancellationToken);
    }
}
