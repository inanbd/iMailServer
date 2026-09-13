using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Security;

/// <summary>
/// Writes the audit trail, with both an in-transaction and a post-rollback path.
/// </summary>
/// <remarks>
/// See <see cref="IAuditTrail"/> for why two paths are needed. In short: a success record
/// must commit with the change it describes, and a failure record must survive the rollback
/// of the very transaction that failed.
/// </remarks>
internal sealed class AuditTrail(
    IAuditRepository repository,
    IDbConnectionFactory connectionFactory,
    IAdminContext adminContext,
    ICorrelationContext correlationContext,
    IEnvironmentInfo environment,
    IClock clock,
    ILogger<AuditTrail> logger) : IAuditTrail
{
    private readonly List<PendingRecord> _deferred = [];

    public bool HasDeferredRecords => _deferred.Count > 0;

    public Task RecordAsync(
        AuditDescriptor descriptor,
        AuditResult result,
        string? detail,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(descriptor);

        // Joins the ambient transaction via the repository, so this record commits with the
        // change it describes, or not at all.
        return repository.AppendAsync(Build(descriptor, result, detail), cancellationToken);
    }

    public void QueueDeferred(AuditDescriptor descriptor, AuditResult result, string? detail)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        _deferred.Add(new PendingRecord(Build(descriptor, result, detail)));
    }

    public async Task FlushDeferredAsync(CancellationToken cancellationToken)
    {
        if (_deferred.Count == 0)
        {
            return;
        }

        PendingRecord[] pending = [.. _deferred];
        _deferred.Clear();

        try
        {
            // A fresh connection, deliberately bypassing the repository's ambient-session
            // logic. By this point the failed transaction has rolled back; writing through
            // the ambient session would either be rolled back too or, worse, try to use a
            // transaction that no longer exists.
            await using System.Data.Common.DbConnection connection = await connectionFactory
                .OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);

            foreach (PendingRecord item in pending)
            {
                await connection.ExecuteAsync(new CommandDefinition(
                    AuditSql.Insert,
                    ToParameters(item.Record),
                    cancellationToken: cancellationToken)).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            // Never rethrow. This runs inside the finally of the outermost exception
            // behavior: throwing here would replace the request's real exception - the one
            // that says what actually went wrong - with a secondary audit-write failure.
            logger.LogError(
                ex,
                "Failed to write {DeferredCount} deferred audit record(s). The actions they " +
                "describe are still recorded in the structured log under correlation id " +
                "{CorrelationId}.",
                pending.Length,
                correlationContext.CorrelationId.Value);
        }
    }

    private AuditRecord Build(AuditDescriptor descriptor, AuditResult result, string? detail) =>
        AuditRecord.Create(
            clock.UtcNow,
            adminContext.Administrator,
            descriptor.Action,
            descriptor.TargetType,
            descriptor.TargetIdentifier,
            result,
            // Only the descriptor's own detail, or a caller-supplied override. Nothing is
            // reflected out of the request object, which is what keeps secrets out of this
            // table by construction rather than by vigilance.
            detail ?? descriptor.Detail,
            environment.MachineName,
            adminContext.SessionIdentifier,
            correlationContext.CorrelationId);

    private static object ToParameters(AuditRecord record) => new
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
    };

    private sealed record PendingRecord(AuditRecord Record);

    private static class AuditSql
    {
        public const string Insert = """
            INSERT INTO AuditRecords
                (Id, TimestampUtc, Administrator, Action, TargetType, TargetIdentifier,
                 Result, Detail, MachineName, SessionIdentifier, CorrelationId)
            VALUES
                (@Id, @TimestampUtc, @Administrator, @Action, @TargetType, @TargetIdentifier,
                 @Result, @Detail, @MachineName, @SessionIdentifier, @CorrelationId)
            """;
    }
}
