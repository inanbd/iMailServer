using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Security;

/// <summary>
/// Buffers security events during a request and writes them afterwards on their own connection.
/// </summary>
/// <remarks>
/// <para>
/// See <see cref="ISecurityEventRecorder"/> for the two reasons nothing is written during the
/// request: an event recorded inside a failing transaction would be rolled back with it, and a
/// second connection opened while a write transaction is open blocks under SQLite until the
/// busy timeout expires — losing the event <i>and</i> stalling the request.
/// </para>
/// <para>
/// Scoped, so the buffer is per request. The scope is disposed when the request ends, which is
/// after <c>UnhandledExceptionBehavior</c> has flushed it.
/// </para>
/// </remarks>
public sealed class SecurityEventRecorder(
    IDbConnectionFactory connectionFactory,
    ICorrelationContext correlationContext,
    IEnvironmentInfo environment,
    IClock clock,
    ILogger<SecurityEventRecorder> logger) : ISecurityEventRecorder
{
    private const string InsertSql = """
        INSERT INTO SecurityEvents
            (Id, TimestampUtc, EventType, Subject, Origin, Description,
             MachineName, CorrelationId, IsAlarming)
        VALUES
            (@Id, @TimestampUtc, @EventType, @Subject, @Origin, @Description,
             @MachineName, @CorrelationId, @IsAlarming)
        """;

    /// <summary>Bound on the stored description, so a long message cannot bloat the table.</summary>
    private const int MaxDescriptionLength = 1024;

    /// <summary>
    /// Bound on the buffer, so a single request cannot accumulate unbounded events.
    /// </summary>
    /// <remarks>
    /// No legitimate request records more than a handful. A cap means a bug in a loop cannot
    /// turn one request into an out-of-memory condition.
    /// </remarks>
    private const int MaxBufferedEvents = 64;

    private readonly List<SecurityEvent> _pending = [];

    public bool HasPendingEvents => _pending.Count > 0;

    public Task RecordAsync(
        SecurityEventType eventType,
        string? subject,
        string? origin,
        string description,
        CancellationToken cancellationToken)
    {
        SecurityEvent securityEvent = SecurityEvent.Create(
            clock.UtcNow,
            eventType,
            Truncate(subject, 256),
            Truncate(origin, 256),
            Truncate(description, MaxDescriptionLength) ?? eventType.ToString(),
            environment.MachineName,
            correlationContext.CorrelationId);

        // Logged immediately, buffered for the database. The structured log is written
        // synchronously so the event survives even if the table write later fails - and so
        // that an operator tailing the log sees a brute-force attempt as it happens rather
        // than once the request completes.
        if (securityEvent.IsAlarming)
        {
            logger.LogWarning(
                "Security event {SecurityEventType}: {Description} (subject {Subject}, origin {Origin})",
                eventType,
                securityEvent.Description,
                securityEvent.Subject ?? "(none)",
                securityEvent.Origin ?? "(unknown)");
        }
        else
        {
            logger.LogInformation(
                "Security event {SecurityEventType}: {Description}",
                eventType,
                securityEvent.Description);
        }

        if (_pending.Count < MaxBufferedEvents)
        {
            _pending.Add(securityEvent);
        }
        else
        {
            logger.LogWarning(
                "The security event buffer is full ({Limit}); {SecurityEventType} was logged " +
                "but not persisted. This suggests a loop recording events.",
                MaxBufferedEvents,
                eventType);
        }

        return Task.CompletedTask;
    }

    public async Task FlushAsync(CancellationToken cancellationToken)
    {
        if (_pending.Count == 0)
        {
            return;
        }

        SecurityEvent[] toWrite = [.. _pending];
        _pending.Clear();

        try
        {
            // A dedicated connection, deliberately bypassing the ambient session. Safe here
            // because the caller guarantees no write transaction is open - see the interface
            // remarks for what happens otherwise.
            await using System.Data.Common.DbConnection connection = await connectionFactory
                .OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);

            foreach (SecurityEvent securityEvent in toWrite)
            {
                await connection.ExecuteAsync(new CommandDefinition(
                    InsertSql,
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
                    cancellationToken: cancellationToken)).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            // Swallowed, but never silently: every event was already written to the structured
            // log in RecordAsync, so the record survives even when the table write does not.
            // Rethrowing would let a logging problem abort an authentication rejection.
            logger.LogError(
                ex,
                "Failed to persist {EventCount} security event(s). They remain in the " +
                "structured log under correlation id {CorrelationId}.",
                toWrite.Length,
                correlationContext.CorrelationId.Value);
        }
    }

    private static string? Truncate(string? value, int maxLength)
    {
        if (value is null)
        {
            return null;
        }

        return value.Length <= maxLength
            ? value
            : string.Concat(value.AsSpan(0, maxLength - 1), "…");
    }
}
