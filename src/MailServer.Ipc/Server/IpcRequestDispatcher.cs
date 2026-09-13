using MailServer.Application.Abstractions.Security;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Ipc.Protocol;
using MediatR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace MailServer.Ipc.Server;

/// <summary>
/// Turns one <see cref="IpcRequest"/> into a MediatR dispatch and an <see cref="IpcResponse"/>.
/// </summary>
/// <remarks>
/// <para>
/// The order of checks is load-bearing, and each one runs before any handler is reached:
/// </para>
/// <list type="number">
///   <item><description>Protocol version — an incompatible client gets one clear message
///   rather than a cascade of failures.</description></item>
///   <item><description>Command registry — an unregistered name never resolves to a type.</description></item>
///   <item><description>Session — validated against the manager, which also slides the idle
///   timer. Only then is the admin context populated.</description></item>
/// </list>
/// <para>
/// A DI scope is created per request, which is what gives each one its own correlation
/// context, admin context and ambient transaction slot, and what guarantees two concurrent
/// operations cannot see each other's transaction.
/// </para>
/// </remarks>
internal sealed class IpcRequestDispatcher(
    IServiceScopeFactory scopeFactory,
    IpcCommandRegistry registry,
    IAdminSessionManager sessions,
    ILogger<IpcRequestDispatcher> logger)
{
    public async Task<IpcResponse> DispatchAsync(
        IpcRequest request,
        IpcCallerIdentity caller,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(caller);

        // Sanitised on arrival: an unsanitised id from a lower-trust process is written to
        // every subsequent log line, and a caller able to inject newlines into that could
        // forge log entries.
        CorrelationId correlationId = CorrelationId.FromExternal(request.CorrelationId);

        if (request.ProtocolVersion < IpcProtocol.MinimumSupportedVersion ||
            request.ProtocolVersion > IpcProtocol.Version)
        {
            logger.LogWarning(
                "Rejected an IPC request from {Caller}: protocol version {ClientVersion} is " +
                "outside the supported range {MinVersion}-{MaxVersion}.",
                caller.Name,
                request.ProtocolVersion,
                IpcProtocol.MinimumSupportedVersion,
                IpcProtocol.Version);

            return IpcResponse.Failed(
                request.RequestId,
                new IpcError
                {
                    Kind = IpcErrorKind.ProtocolMismatch,
                    Code = "ipc.protocol_mismatch",
                    Message =
                        $"This service speaks IPC protocol version {IpcProtocol.Version}; the " +
                        $"administration application sent version {request.ProtocolVersion}. " +
                        "Upgrade the administration application to match the service.",
                },
                correlationId.Value);
        }

        if (!registry.TryResolve(request.Command, out IpcCommandDescriptor? descriptor))
        {
            // Warning, not Debug: an unknown command on an ACL-restricted administrative pipe
            // is either a version mismatch or somebody probing.
            logger.LogWarning(
                "Rejected unknown IPC command '{Command}' from {Caller}.",
                request.Command,
                caller.Name);

            return IpcResponse.Failed(
                request.RequestId,
                new IpcError
                {
                    Kind = IpcErrorKind.UnknownCommand,
                    Code = "ipc.unknown_command",
                    Message = $"'{request.Command}' is not a recognised command.",
                },
                correlationId.Value);
        }

        // ---- Session ----------------------------------------------------------------------
        AdminSession? session = null;

        if (descriptor.RequiresSession)
        {
            SessionValidationResult validation = await sessions
                .ValidateAsync(request.SessionToken, cancellationToken)
                .ConfigureAwait(false);

            if (!validation.IsValid)
            {
                return await RejectUnauthenticatedAsync(
                    request,
                    descriptor,
                    caller,
                    validation.Failure,
                    correlationId,
                    cancellationToken).ConfigureAwait(false);
            }

            session = validation.Session;
        }

        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();

        scope.ServiceProvider
            .GetRequiredService<ICorrelationContext>()
            .Initialize(correlationId);

        // Identity is established BEFORE dispatch, so the authorization behavior has something
        // to enforce and every log line is already attributed.
        //
        // For an anonymous command the context is deliberately left unauthenticated with no
        // permissions. The authorization behavior skips the permission check for those four
        // commands by their IAnonymousRequest marker, not by anything the caller sends - so a
        // client cannot obtain permissions merely by omitting a token.
        if (session is not null)
        {
            scope.ServiceProvider
                .GetRequiredService<IAdminContextInitializer>()
                .Assign(
                    session.Administrator,
                    session.Id.ToString(),
                    session.Permissions,
                    isSystem: false,
                    session.MustChangePassword);
        }

        ISender sender = scope.ServiceProvider.GetRequiredService<ISender>();

        try
        {
            object? payload = IpcFrame.DeserializePayload(request.Payload, descriptor.RequestType);

            if (payload is null)
            {
                return IpcResponse.Failed(
                    request.RequestId,
                    new IpcError
                    {
                        Kind = IpcErrorKind.Validation,
                        Code = "ipc.payload_missing",
                        Message = $"Command '{request.Command}' requires a payload.",
                    },
                    correlationId.Value);
            }

            object? result = await sender.Send(payload, cancellationToken).ConfigureAwait(false);

            return IpcResponse.Ok(
                request.RequestId,
                result is null ? null : IpcFrame.SerializePayload(result),
                correlationId.Value);
        }
        catch (Exception ex)
        {
            // The pipeline has already logged this with full detail under the same correlation
            // id; here it is only translated for the wire. Logging it again would double every
            // failure in the log.
            logger.LogDebug(
                "IPC command {Command} failed: {ExceptionType}.",
                request.Command,
                ex.GetType().Name);

            return IpcResponse.Failed(
                request.RequestId,
                IpcErrorMapper.Map(ex, correlationId),
                correlationId.Value);
        }
    }

    /// <summary>
    /// Refuses a request that presented no valid session, and records why.
    /// </summary>
    /// <remarks>
    /// The <i>client</i> is told only that it must sign in again. The specific reason — unknown
    /// token, idle timeout, absolute expiry, revoked — goes to the security event log and the
    /// service log, where an operator can see it and a caller cannot. An unknown token is
    /// recorded as alarming because, unlike an expiry, it means somebody presented a value that
    /// was never issued.
    /// </remarks>
    private async Task<IpcResponse> RejectUnauthenticatedAsync(
        IpcRequest request,
        IpcCommandDescriptor descriptor,
        IpcCallerIdentity caller,
        SessionValidationFailure failure,
        CorrelationId correlationId,
        CancellationToken cancellationToken)
    {
        logger.LogWarning(
            "Refused {Command} from {Caller}: {SessionFailure}.",
            descriptor.Name,
            caller.Name,
            failure);

        if (failure is SessionValidationFailure.Unknown or SessionValidationFailure.Revoked)
        {
            // Recorded on its own scope, because the request scope is never created for a
            // rejected request - there is no identity to put in it.
            await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();

            scope.ServiceProvider
                .GetRequiredService<ICorrelationContext>()
                .Initialize(correlationId);

            ISecurityEventRecorder recorder =
                scope.ServiceProvider.GetRequiredService<ISecurityEventRecorder>();

            await recorder
                .RecordAsync(
                    SecurityEventType.InvalidSessionPresented,
                    subject: null,
                    caller.Name,
                    $"A request for '{descriptor.Name}' presented a session token that was " +
                    $"{(failure == SessionValidationFailure.Unknown ? "not recognised" : "revoked")}.",
                    cancellationToken)
                .ConfigureAwait(false);

            // Flushed explicitly: this path never enters the MediatR pipeline, so the
            // behavior that normally flushes the buffer does not run. There is no transaction
            // open here, so writing immediately is safe.
            await recorder.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        string message = failure switch
        {
            SessionValidationFailure.IdleTimeout =>
                "The session ended after a period of inactivity. Sign in again to continue.",
            SessionValidationFailure.Expired =>
                "The session has reached its maximum lifetime. Sign in again to continue.",
            SessionValidationFailure.Revoked =>
                "The session was ended. Sign in again to continue.",
            _ =>
                "Sign in to continue.",
        };

        return IpcResponse.Failed(
            request.RequestId,
            new IpcError
            {
                Kind = IpcErrorKind.Unauthenticated,
                Code = "ipc.unauthenticated",
                Message = message,
            },
            correlationId.Value);
    }
}

/// <summary>
/// The transport-level identity of the connecting process.
/// </summary>
/// <remarks>
/// <para>
/// This is the <b>outer</b> of two layers. The pipe ACL has already restricted connections to
/// local administrators, and this records which one — used as the origin on security events, so
/// a failed sign-in can be attributed to a Windows account even though the sign-in itself
/// failed.
/// </para>
/// <para>
/// It no longer confers permissions. From Milestone 2, permissions come exclusively from an
/// authenticated session; Windows identity alone gets a caller as far as the sign-in screen and
/// no further.
/// </para>
/// </remarks>
internal sealed record IpcCallerIdentity(
    string Name,
    string? SessionIdentifier,
    AdminPermission Permissions);
