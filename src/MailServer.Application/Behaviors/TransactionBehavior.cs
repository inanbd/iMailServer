using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Persistence;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Behaviors;

/// <summary>
/// Pipeline stage 7 of 8. Wraps requests marked <see cref="ITransactionalRequest"/> in a
/// single database transaction.
/// </summary>
/// <remarks>
/// <para>
/// One transaction per use case. A handler that writes a domain row, an audit row and a DNS
/// check row either writes all three or none - there is no state in which the audit trail
/// describes a change that did not happen.
/// </para>
/// <para>
/// Requests <b>not</b> marked transactional pass straight through. Queries in particular
/// must never open a transaction: under SQLite a read transaction is unnecessary thanks to
/// WAL, and any transaction at all is a needless round trip.
/// </para>
/// <para>
/// No network I/O may occur inside the handler this wraps. An SMTP conversation, a DNS
/// lookup or an ACME round trip inside a transaction holds a writer for the remote server's
/// response time. Delivery happens outside; its outcome is recorded in a second, short
/// transaction.
/// </para>
/// </remarks>
public sealed class TransactionBehavior<TRequest, TResponse>(
    ITransactionManager transactionManager,
    ILogger<TransactionBehavior<TRequest, TResponse>> logger)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : notnull
{
    public async Task<TResponse> Handle(
        TRequest request,
        RequestHandlerDelegate<TResponse> next,
        CancellationToken cancellationToken)
    {
        if (request is not ITransactionalRequest)
        {
            return await next(cancellationToken).ConfigureAwait(false);
        }

        string requestName = typeof(TRequest).Name;
        logger.LogDebug("Opening transaction for {RequestName}.", requestName);

        TResponse response = await transactionManager.ExecuteScopedAsync(
            async ct => await next(ct).ConfigureAwait(false),
            cancellationToken).ConfigureAwait(false);

        logger.LogDebug("Committed transaction for {RequestName}.", requestName);
        return response;
    }
}
