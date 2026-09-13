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
/// Creates a DI scope per request. That is what gives each request its own correlation
/// context, admin context and ambient transaction slot, and what guarantees two concurrent
/// admin operations cannot see each other's transaction.
/// </para>
/// </remarks>
internal sealed class IpcRequestDispatcher(
    IServiceScopeFactory scopeFactory,
    IpcCommandRegistry registry,
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
            // Logged at Warning, not Debug: an unknown command on an ACL-restricted
            // administrative pipe is either a version mismatch or someone probing.
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

        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();

        // Establish identity and correlation BEFORE dispatch, so the authorization behavior
        // has something to enforce and every log line is already correlated.
        scope.ServiceProvider
            .GetRequiredService<ICorrelationContext>()
            .Initialize(correlationId);

        scope.ServiceProvider
            .GetRequiredService<IAdminContextInitializer>()
            .Assign(caller.Name, caller.SessionIdentifier, caller.Permissions);

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
            // The pipeline has already logged this with full detail under the same
            // correlation id; here it is only translated for the wire. Logging it again
            // would double every failure in the log.
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
}

/// <summary>
/// The authenticated identity on the far end of the pipe.
/// </summary>
/// <remarks>
/// Milestone 1 populates this from the Windows identity of the connecting process, which the
/// pipe ACL has already constrained to local administrators. Milestone 2 adds the master
/// password session on top, narrowing <see cref="Permissions"/> per session without changing
/// anything downstream.
/// </remarks>
internal sealed record IpcCallerIdentity(
    string Name,
    string? SessionIdentifier,
    AdminPermission Permissions);
