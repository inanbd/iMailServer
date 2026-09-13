using System.IO.Pipes;
using System.Security.Principal;
using MailServer.Ipc.Protocol;
using Microsoft.Extensions.Logging;

namespace MailServer.Ipc.Client;

/// <summary>Connection settings for the administration client.</summary>
public sealed class IpcClientOptions
{
    /// <summary>The service's machine. "." is the local machine.</summary>
    public string ServerName { get; set; } = ".";

    public string PipeName { get; set; } = "AetherMail.Admin";

    public int MaxFrameBytes { get; set; } = 4 * 1024 * 1024;

    public int ConnectTimeoutMs { get; set; } = 5_000;

    public int RequestTimeoutSeconds { get; set; } = 60;
}

/// <summary>
/// The administration application's end of the named pipe.
/// </summary>
/// <remarks>
/// <para>
/// Requests are serialised through a semaphore because a single pipe carries one
/// conversation: two overlapping requests would interleave their frames and each would read
/// the other's response. The <c>RequestId</c> in the envelope is checked as well, so a
/// desynchronised stream is detected rather than silently returning the wrong answer to the
/// wrong caller.
/// </para>
/// <para>
/// Reconnects transparently. The service can restart - during an upgrade, or because an
/// operator restarted it - and the admin application should recover on the next request
/// rather than requiring a relaunch.
/// </para>
/// </remarks>
public sealed class IpcClient : IAsyncDisposable
{
    private readonly IpcClientOptions _options;
    private readonly ILogger<IpcClient> _logger;
    private readonly SemaphoreSlim _requestGate = new(1, 1);

    private NamedPipeClientStream? _pipe;
    private bool _disposed;

    public IpcClient(IpcClientOptions options, ILogger<IpcClient> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;
        _logger = logger;
    }

    /// <summary>True when a pipe is currently open.</summary>
    public bool IsConnected => _pipe is { IsConnected: true };

    /// <summary>
    /// Sends a command and returns the deserialised result.
    /// </summary>
    /// <exception cref="IpcRequestException">The server returned an error.</exception>
    public async Task<TResponse?> SendAsync<TRequest, TResponse>(
        string command,
        TRequest payload,
        string? correlationId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(command);
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _requestGate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            IpcResponse response = await SendCoreAsync(
                command,
                IpcFrame.SerializePayload(payload),
                correlationId,
                cancellationToken).ConfigureAwait(false);

            if (!response.Success)
            {
                throw new IpcRequestException(
                    response.Error ?? new IpcError
                    {
                        Kind = IpcErrorKind.Internal,
                        Code = "ipc.malformed_error",
                        Message = "The server reported a failure but supplied no detail.",
                    },
                    response.CorrelationId);
            }

            return IpcFrame.DeserializePayload<TResponse>(response.Payload);
        }
        finally
        {
            _requestGate.Release();
        }
    }

    private async Task<IpcResponse> SendCoreAsync(
        string command,
        string payload,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        // One transparent retry. A pipe broken while idle - because the service restarted -
        // is indistinguishable from a healthy one until the write fails, so the only way to
        // detect it is to try.
        for (int attempt = 1; attempt <= 2; attempt++)
        {
            try
            {
                NamedPipeClientStream pipe = await EnsureConnectedAsync(cancellationToken)
                    .ConfigureAwait(false);

                IpcRequest request = new()
                {
                    ProtocolVersion = IpcProtocol.Version,
                    RequestId = Guid.CreateVersion7().ToString("N"),
                    Command = command,
                    Payload = payload,
                    CorrelationId = correlationId,
                };

                using CancellationTokenSource timeout = CancellationTokenSource
                    .CreateLinkedTokenSource(cancellationToken);

                timeout.CancelAfter(TimeSpan.FromSeconds(_options.RequestTimeoutSeconds));

                await IpcFrame
                    .WriteAsync(pipe, request, _options.MaxFrameBytes, timeout.Token)
                    .ConfigureAwait(false);

                IpcResponse? response = await IpcFrame
                    .ReadAsync<IpcResponse>(pipe, _options.MaxFrameBytes, timeout.Token)
                    .ConfigureAwait(false);

                if (response is null)
                {
                    throw new IOException("The service closed the connection without responding.");
                }

                if (!string.Equals(response.RequestId, request.RequestId, StringComparison.Ordinal))
                {
                    // The stream is desynchronised. Returning this response would hand one
                    // caller another caller's data - silently, and possibly across a
                    // permission boundary.
                    await DisconnectAsync().ConfigureAwait(false);

                    throw new IpcRequestException(
                        new IpcError
                        {
                            Kind = IpcErrorKind.Internal,
                            Code = "ipc.response_mismatch",
                            Message =
                                "The service returned a response for a different request. The " +
                                "connection has been reset.",
                        },
                        response.CorrelationId);
                }

                return response;
            }
            catch (Exception ex) when (attempt == 1 && IsRecoverable(ex))
            {
                _logger.LogWarning(
                    "The connection to the mail service was lost ({Reason}). Reconnecting.",
                    ex.GetType().Name);

                await DisconnectAsync().ConfigureAwait(false);
            }
        }

        throw new IpcRequestException(
            new IpcError
            {
                Kind = IpcErrorKind.Internal,
                Code = "ipc.unreachable",
                Message =
                    $"Could not reach the mail service on pipe '{_options.PipeName}'. Check that " +
                    "the AetherMail Server service is running.",
            },
            correlationId);
    }

    private static bool IsRecoverable(Exception exception) =>
        exception is IOException or ObjectDisposedException or InvalidOperationException;

    private async Task<NamedPipeClientStream> EnsureConnectedAsync(CancellationToken cancellationToken)
    {
        if (_pipe is { IsConnected: true } existing)
        {
            return existing;
        }

        await DisconnectAsync().ConfigureAwait(false);

        NamedPipeClientStream pipe = new(
            _options.ServerName,
            _options.PipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,

            // Identification, not Impersonation or Delegation. The service needs to know who
            // is calling; it must never be able to act as them. Granting more impersonation
            // than the server needs is a privilege-escalation vector if the service is ever
            // compromised.
            TokenImpersonationLevel.Identification);

        try
        {
            await pipe.ConnectAsync(_options.ConnectTimeoutMs, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            await pipe.DisposeAsync().ConfigureAwait(false);

            throw new IpcRequestException(
                new IpcError
                {
                    Kind = IpcErrorKind.Internal,
                    Code = "ipc.connect_timeout",
                    Message =
                        $"The AetherMail Server service did not accept a connection on pipe " +
                        $"'{_options.PipeName}' within {_options.ConnectTimeoutMs} ms. Check that " +
                        "the service is running and that you are a member of the local " +
                        "Administrators group.",
                },
                correlationId: null);
        }

        _pipe = pipe;
        _logger.LogInformation("Connected to the mail service on pipe '{PipeName}'.", _options.PipeName);

        return pipe;
    }

    private async Task DisconnectAsync()
    {
        if (_pipe is null)
        {
            return;
        }

        try
        {
            await _pipe.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error while closing the IPC pipe.");
        }
        finally
        {
            _pipe = null;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        await DisconnectAsync().ConfigureAwait(false);
        _requestGate.Dispose();
    }
}

/// <summary>The service rejected or failed a request.</summary>
public sealed class IpcRequestException : Exception
{
    public IpcRequestException(IpcError error, string? correlationId)
        : base(error?.Message ?? "The request failed.")
    {
        ArgumentNullException.ThrowIfNull(error);

        Error = error;
        CorrelationId = correlationId;
    }

    /// <summary>The structured error. Switch on <see cref="IpcError.Code"/>, never the message.</summary>
    public IpcError Error { get; }

    /// <summary>Correlation id, for finding the full detail in the service log.</summary>
    public string? CorrelationId { get; }
}
