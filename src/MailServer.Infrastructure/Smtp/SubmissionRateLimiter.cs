using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Persistence;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Smtp;

/// <summary>
/// Counts what a mailbox has submitted, from the record of what was actually accepted.
/// </summary>
/// <remarks>
/// <para>
/// <b>Counted from the database rather than from memory.</b> An in-memory window would be faster
/// and would also be cleared by a restart — and a restart is not a rare event on a Windows
/// server, so a limit that forgets across one is a limit an attacker gets to reset by waiting
/// for Patch Tuesday. The <c>Messages</c> table is the true record and survives.
/// </para>
/// <para>
/// <b>What this does not bound.</b> A message is counted once it has been accepted, so messages
/// already in flight on other connections are not yet visible. A mailbox can therefore overshoot
/// by roughly the number of connections it holds open — which is itself bounded by
/// <c>MaxConcurrentConnectionsPerIp</c>. The overshoot is bounded and small; a counter that tried
/// to reserve capacity before DATA would have to release it on every failure path, and a
/// reservation leaked on one of those paths locks a mailbox out for an hour.
/// </para>
/// </remarks>
internal sealed class SubmissionRateLimiter(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect,
    IOptionsMonitor<MailServerOptions> options,
    IClock clock)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), ISubmissionRateLimiter
{
    /// <summary>The window the limit applies over.</summary>
    internal static TimeSpan Window => TimeSpan.FromHours(1);

    /// <inheritdoc />
    public Task<SubmissionRateDecision> CheckAsync(EmailAddress mailbox, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(mailbox);

        int limit = options.CurrentValue.Limits.MaxMessagesPerMailboxPerHour;

        return ExecuteAsync(async (session, ct) =>
        {
            long count = await session.Connection.ExecuteScalarAsync<long>(Command(
                session,
                """
                SELECT COUNT(*)
                FROM   Messages
                WHERE  AuthenticatedAs = @Mailbox
                AND    ReceivedUtc >= @Since
                """,
                new
                {
                    Mailbox = mailbox.NormalizedValue,
                    Since = clock.UtcNow - Window,
                },
                ct)).ConfigureAwait(false);

            return new SubmissionRateDecision(count < limit, count, limit, Window);
        }, cancellationToken);
    }
}
