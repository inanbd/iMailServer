using MailServer.Application.Exceptions;
using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;
using MailServer.Ipc.Protocol;

namespace MailServer.Ipc.Server;

/// <summary>
/// Converts an exception into a wire error.
/// </summary>
/// <remarks>
/// <para>
/// <b>Known failures are described; unknown ones are not.</b> Validation errors, domain rule
/// violations and authorization denials are all deliberate, well-modelled outcomes whose
/// messages were written to be read by an administrator, so they cross the wire intact.
/// </para>
/// <para>
/// An <i>unexpected</i> exception is different. Its message can contain a SQL statement, a
/// file path, a connection string fragment or a stack frame - none of which belongs in a UI,
/// and some of which is a disclosure. The client gets a generic message plus the correlation
/// id, and the operator finds the full detail in the service log under that id.
/// </para>
/// </remarks>
internal static class IpcErrorMapper
{
    public static IpcError Map(Exception exception, CorrelationId correlationId)
    {
        ArgumentNullException.ThrowIfNull(exception);

        return exception switch
        {
            ValidationFailedException validation => new IpcError
            {
                Kind = IpcErrorKind.Validation,
                Code = validation.Code,
                Message = validation.Message,
                ValidationErrors = validation.Errors,
            },

            AuthorizationFailedException authorization => new IpcError
            {
                Kind = IpcErrorKind.Authorization,
                Code = authorization.Code,
                Message = authorization.Message,
            },

            MaintenanceModeException maintenance => new IpcError
            {
                Kind = IpcErrorKind.Maintenance,
                Code = maintenance.Code,
                Message = maintenance.Message,
            },

            EntityNotFoundException notFound => new IpcError
            {
                Kind = IpcErrorKind.NotFound,
                Code = notFound.Code,
                Message = notFound.Message,
            },

            DuplicateEntityException duplicate => new IpcError
            {
                Kind = IpcErrorKind.Conflict,
                Code = duplicate.Code,
                Message = duplicate.Message,
            },

            // Every remaining domain exception: the message is a deliberate explanation of a
            // business rule, written for an administrator to read.
            DomainException domain => new IpcError
            {
                Kind = IpcErrorKind.DomainRule,
                Code = domain.Code,
                Message = domain.Message,
            },

            ApplicationLayerException application => new IpcError
            {
                Kind = IpcErrorKind.Internal,
                Code = application.Code,
                Message = application.Message,
            },

            OperationCanceledException => new IpcError
            {
                Kind = IpcErrorKind.ServiceStopping,
                Code = "service.stopping",
                Message = "The service is shutting down and did not complete the request.",
            },

            // Anything else. Deliberately opaque.
            _ => new IpcError
            {
                Kind = IpcErrorKind.Internal,
                Code = "internal.error",
                Message =
                    "The server encountered an unexpected error. See the service log for " +
                    $"correlation id {correlationId.Value}.",
            },
        };
    }
}
