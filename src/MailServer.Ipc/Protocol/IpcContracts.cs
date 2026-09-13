using System.Text.Json.Serialization;

namespace MailServer.Ipc.Protocol;

/// <summary>
/// Wire protocol constants.
/// </summary>
/// <remarks>
/// During an upgrade an already-running admin application may talk to a newly-upgraded
/// service. Versioning the protocol explicitly means that mismatch produces a clear,
/// actionable message instead of a deserialisation failure that looks like corruption.
/// </remarks>
public static class IpcProtocol
{
    /// <summary>
    /// Current protocol version. Increment on any breaking change to the envelope shape.
    /// </summary>
    public const int Version = 1;

    /// <summary>
    /// Oldest client version this server still accepts. Kept equal to
    /// <see cref="Version"/> until there is a compatibility story worth supporting.
    /// </summary>
    public const int MinimumSupportedVersion = 1;

    /// <summary>Absolute ceiling on a single frame, independent of configuration.</summary>
    /// <remarks>
    /// A configured limit can be raised by an operator; this cannot. It bounds the damage a
    /// misconfiguration can do, because the length prefix is attacker-influenced data read
    /// before any allocation.
    /// </remarks>
    public const int AbsoluteMaxFrameBytes = 64 * 1024 * 1024;
}

/// <summary>A request from the administration application to the service.</summary>
public sealed record IpcRequest
{
    /// <summary>Protocol version spoken by the client.</summary>
    public required int ProtocolVersion { get; init; }

    /// <summary>Correlates this request with its response on the same connection.</summary>
    public required string RequestId { get; init; }

    /// <summary>
    /// The logical command name, e.g. <c>Domains.Create</c>.
    /// </summary>
    /// <remarks>
    /// <b>A name, never a .NET type name.</b> The server resolves it through an explicit
    /// registry. Accepting an assembly-qualified type name and calling
    /// <c>Type.GetType</c> on it would let anyone who can reach the pipe instantiate
    /// arbitrary types in the service process - a remote code execution primitive handed
    /// over for the sake of saving a dictionary.
    /// </remarks>
    public required string Command { get; init; }

    /// <summary>JSON payload, deserialised into the registered request type for the command.</summary>
    public string? Payload { get; init; }

    /// <summary>
    /// Correlation id from the client, so one operation is traceable across both processes.
    /// Sanitised on arrival before it reaches any log line.
    /// </summary>
    public string? CorrelationId { get; init; }
}

/// <summary>A response from the service.</summary>
public sealed record IpcResponse
{
    public required int ProtocolVersion { get; init; }

    public required string RequestId { get; init; }

    public required bool Success { get; init; }

    /// <summary>JSON payload of the result, when <see cref="Success"/> is true.</summary>
    public string? Payload { get; init; }

    /// <summary>Error detail, when <see cref="Success"/> is false.</summary>
    public IpcError? Error { get; init; }

    public string? CorrelationId { get; init; }

    public static IpcResponse Ok(string requestId, string? payload, string? correlationId) => new()
    {
        ProtocolVersion = IpcProtocol.Version,
        RequestId = requestId,
        Success = true,
        Payload = payload,
        CorrelationId = correlationId,
    };

    public static IpcResponse Failed(string requestId, IpcError error, string? correlationId) => new()
    {
        ProtocolVersion = IpcProtocol.Version,
        RequestId = requestId,
        Success = false,
        Error = error,
        CorrelationId = correlationId,
    };
}

/// <summary>A structured error.</summary>
/// <remarks>
/// The client switches on <see cref="Code"/>, never on <see cref="Message"/>. Rewording a
/// message for clarity must not break a caller, and translating one must not either.
/// </remarks>
public sealed record IpcError
{
    public required IpcErrorKind Kind { get; init; }

    /// <summary>Stable machine-readable code, e.g. <c>domain.duplicate</c>.</summary>
    public required string Code { get; init; }

    /// <summary>Human-readable message for the administrator.</summary>
    public required string Message { get; init; }

    /// <summary>Validation failures keyed by property name.</summary>
    public IReadOnlyDictionary<string, string[]>? ValidationErrors { get; init; }
}

/// <summary>Broad classification of a failure, so the UI can react appropriately.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<IpcErrorKind>))]
public enum IpcErrorKind
{
    /// <summary>An unexpected failure. The UI shows a generic message and a correlation id.</summary>
    Internal = 0,

    /// <summary>The request failed validation. The UI highlights the offending fields.</summary>
    Validation = 1,

    /// <summary>The session lacks the required permission. The UI may prompt to unlock.</summary>
    Authorization = 2,

    /// <summary>A domain rule rejected the operation. The UI shows the message verbatim.</summary>
    DomainRule = 3,

    /// <summary>The target does not exist.</summary>
    NotFound = 4,

    /// <summary>An object with the same natural key already exists.</summary>
    Conflict = 5,

    /// <summary>The server is in a maintenance mode that forbids this operation.</summary>
    Maintenance = 6,

    /// <summary>The client's protocol version is not supported.</summary>
    ProtocolMismatch = 7,

    /// <summary>The command name is not in the server's registry.</summary>
    UnknownCommand = 8,

    /// <summary>The service is stopping and is no longer accepting work.</summary>
    ServiceStopping = 9,
}
