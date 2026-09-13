using System.Data.Common;
using Dapper;
using MailServer.Application.Abstractions.Persistence;

namespace MailServer.Infrastructure.Persistence;

/// <summary>
/// Base for Dapper-backed repositories and query services.
/// </summary>
/// <remarks>
/// <para>
/// Handles the one piece of ceremony every data-access class would otherwise repeat: join
/// the ambient transaction when there is one, or open and dispose a short-lived connection
/// when there is not. Getting that wrong in either direction is costly - a repository that
/// always opens its own connection silently escapes the caller's transaction, and one that
/// always expects an ambient session cannot be used outside a command.
/// </para>
/// <para>
/// <b>Dapper stops here.</b> It is a mapper, used only inside this assembly's persistence
/// namespace. No handler, no domain type and no Application abstraction mentions it, so
/// replacing it would touch this folder and nothing else.
/// </para>
/// </remarks>
internal abstract class SqlRepositoryBase(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
{
    protected ISqlDialect Dialect { get; } = dialect;

    /// <summary>Runs data access on the ambient session, or on a short-lived one.</summary>
    protected async Task<T> ExecuteAsync<T>(
        Func<IDbSession, CancellationToken, Task<T>> action,
        CancellationToken cancellationToken)
    {
        if (ambientSession.Current is { } current)
        {
            return await action(current, cancellationToken).ConfigureAwait(false);
        }

        DbConnection connection = await connectionFactory
            .OpenConnectionAsync(cancellationToken)
            .ConfigureAwait(false);

        await using DbSession session = new(connection, transaction: null, ownsConnection: true);

        return await action(session, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Builds a Dapper command bound to the session's connection, transaction and
    /// cancellation token.
    /// </summary>
    /// <remarks>
    /// Every query in this assembly goes through here, which is what guarantees that the
    /// transaction is always passed (a Dapper call that forgets it silently runs outside the
    /// transaction) and that cancellation always flows (one that forgets it cannot be
    /// interrupted at shutdown).
    /// </remarks>
    protected static CommandDefinition Command(
        IDbSession session,
        string sql,
        object? parameters,
        CancellationToken cancellationToken) =>
        new(sql, parameters, session.Transaction, cancellationToken: cancellationToken);
}
