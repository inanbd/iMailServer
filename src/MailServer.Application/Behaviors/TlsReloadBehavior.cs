using MailServer.Application.Abstractions.Certificates;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Behaviors;

/// <summary>
/// Pipeline stage 7 of 9. Reloads the TLS certificate snapshot after a successful request that
/// changed certificate configuration.
/// </summary>
/// <remarks>
/// <para>
/// Registered <b>immediately before</b> <see cref="TransactionBehavior{TRequest,TResponse}"/>,
/// so it wraps it. That placement is the entire design: the code after <c>next()</c> here runs
/// once the transaction has committed, which is the first moment a fresh connection can see the
/// rows the handler wrote.
/// </para>
/// <para>
/// Reloading from inside the transaction instead would rebuild the snapshot from the state
/// before the change — a hot swap that appears to work, logs success, and serves the old
/// certificate. That is a considerably worse failure than not reloading at all, because nothing
/// about it looks wrong.
/// </para>
/// <para>
/// <b>Only on success.</b> An exception propagates without a reload: the transaction rolled
/// back, so there is nothing new to pick up.
/// </para>
/// <para>
/// A reload failure is logged and swallowed. The change itself is committed and correct; what
/// failed is applying it to live connections, and throwing here would report a successful
/// operation as failed and invite the operator to repeat it. The certificate takes effect at
/// the next reload or restart either way.
/// </para>
/// </remarks>
public sealed class TlsReloadBehavior<TRequest, TResponse>(
    ITlsReloadCoordinator coordinator,
    ILogger<TlsReloadBehavior<TRequest, TResponse>> logger)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : notnull
{
    public async Task<TResponse> Handle(
        TRequest request,
        RequestHandlerDelegate<TResponse> next,
        CancellationToken cancellationToken)
    {
        TResponse response = await next(cancellationToken).ConfigureAwait(false);

        if (!coordinator.ReloadRequested)
        {
            return response;
        }

        try
        {
            await coordinator.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "The certificate change for {RequestName} was saved, but the TLS certificate " +
                "snapshot could not be reloaded. New connections will continue to use the " +
                "previous certificate until the next reload or a service restart.",
                typeof(TRequest).Name);
        }

        return response;
    }
}
