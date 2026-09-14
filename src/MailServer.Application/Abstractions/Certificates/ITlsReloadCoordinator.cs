namespace MailServer.Application.Abstractions.Certificates;

/// <summary>
/// Collects a request's intent to reload the TLS certificate snapshot, so the reload happens
/// once, after the transaction has committed.
/// </summary>
/// <remarks>
/// <para>
/// A handler that changes a binding cannot reload the provider itself. It runs inside the
/// request's transaction, so the rows it just wrote are not yet visible on the fresh connection
/// the provider uses to rebuild its snapshot — the reload would either read the previous
/// configuration or block on the writer, depending on the database. Either outcome is a
/// hot-swap that silently does not swap.
/// </para>
/// <para>
/// The same shape as <c>ISecurityEventRecorder</c>, and for the same reason: work that must
/// happen <i>around</i> a transaction rather than inside it is signalled during the request and
/// performed by a pipeline behavior once the transaction's fate is known.
/// </para>
/// <para>
/// A rolled-back request reloads nothing. There is no committed change to pick up, and
/// rebuilding the snapshot would be pure cost.
/// </para>
/// </remarks>
public interface ITlsReloadCoordinator
{
    /// <summary>Records that this request changed something the TLS provider serves.</summary>
    /// <remarks>Idempotent: several calls in one request produce exactly one reload.</remarks>
    void RequestReload();

    /// <summary>True when <see cref="RequestReload"/> was called during this request.</summary>
    bool ReloadRequested { get; }

    /// <summary>Performs the reload, if one was requested. Called after the transaction commits.</summary>
    Task FlushAsync(CancellationToken cancellationToken);
}
